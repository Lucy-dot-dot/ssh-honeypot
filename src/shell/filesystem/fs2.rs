/*!
This module (fs2) implements a simple, in-memory file system with `FileSystem`, `DirEntry`, and `Inode` structs to simulate hierarchical storage and operations critical to a file system. The code provides features like path resolution, creating files/directories, and retrieving directory or file entries using structured interfaces.

# Structs:
- `Inode`: Represents metadata for files or directories, containing attributes such as size, timestamps, permissions, and user/group ID information.
- `DirEntry`: Represents a directory entry in the file system, which can either be a directory containing other directory entries or a file holding file content.
- `FileContent`: Enum that provides different types of file content such as directories, regular files, symbolic links, or devices.
- `FileSystem`: Encapsulates the entire file system, providing methods for interacting with and managing the file system structure.

# Key Features:
1. **Hierarchical Path Resolution**
   - The `resolve_absolute_path` method resolves absolute paths, including handling of `.` and `..` for current and parent directories.

2. **File and Directory Access**
   - The `get_file` and `get_file_mut` methods allow searching and accessing files/directories by paths, returning immutable or mutable references, respectively.

3. **Directory and File Creation**
   - With `create_directory` and `create_file`, users can create directories and files within the file system.

4. **Structured Content Management**
   - `FileContent` allows storing hierarchical structures (directories containing other directories/files) and distinguishes between file types.

## Struct Details:
### `Inode`
Serves as metadata for all files and directories in the file system.
#### Fields:
- `i_mode`: File mode (type and permissions).
- `i_uid`, `i_uid_high`: User ID (split into lower and higher 16 bits).
- `i_gid`, `i_gid_high`: Group ID (split into lower and higher 16 bits).
- `i_size_lo`: File size in bytes (lower 32 bits).
- `i_atime`, `i_ctime`, `i_mtime`: Access, change, and modification times (in seconds since epoch).
- `i_atime_extra`, `i_crtime`, `i_crtime_extra`: Extra time metadata (nanoseconds).
- `i_dtime`: File deletion time.
- `i_links_count`: Number of hard links to the file.
- `i_flags`: File flags for special features.

### `DirEntry`
Represents an entry in the file system, either a file or directory.
#### Fields:
- `inode`: Metadata associated with this file/directory.
- `file_content`: Optional enum representing the content of the file (e.g., directory, regular file, etc.).
- `name`: Name of the file/directory (up to 255 characters, variable-length).
- `leafs`: Vector of child directory entries (for directories).

### `FileContent`
Enum representing the contents of a file.
#### Variants:
- `Directory(Vec<DirEntry>)`: Contains a vector of child directory entries.
- `RegularFile(Vec<u8>)`: Contains binary data representing file content.
- `SymbolicLink(String)`: Target path of a symbolic link.
- `Device(u32, u32)`: Represents a device (major and minor IDs).

### `FileSystem`
Represents the structure of the file system, starting from the root directory.
#### Fields:
- `root`: The root directory entry of the file system.
- `device`: String representing the device/storage backing the file system.

## Method Details:
### `resolve_absolute_path(&self, path: &str) -> String`
Resolves a given file path into an absolute, normalized path by removing `.` (current directory) and `..` (parent directory).

### `get_file(&self, path: &str) -> std::io::Result<&DirEntry>`
Finds and retrieves an immutable reference to the directory entry at the provided path. Returns an error if the file/directory is not found or if there are issues with the path.

### `get_file_mut(&mut self, path: &str) -> std::io::Result<&mut DirEntry>`
Finds and retrieves a mutable reference to the directory entry at the provided path. Returns an error if the path doesn't exist or points to an invalid directory/file.

### `create_directory(&mut self, path: &str) -> std::io::Result<()>`
Creates a new directory at the specified path. If the directory or its parent doesn't exist, or if the parent is not a directory, an appropriate error is returned.

### `create_file(&mut self, path: &str) -> std::io::Result<&mut DirEntry>`
Creates a new regular file at the specified path and returns a mutable reference to the file's directory entry. Handles path normalization and errors for invalid paths or missing parent directories.

## Usage Example:
```rust
let mut fs = FileSystem::default();
fs.create_directory("/home").unwrap();
fs.create_file("/home/user.txt").unwrap();
let resolved_path = fs.resolve_absolute_path("/home/../home/user.txt");
println!("Resolved Path: {}", resolved_path);
let file = fs.get_file("/home/user.txt").unwrap();
println!("Retrieved File: {:?}", file);
```

This module creates a lightweight simulation of a file system, enabling basic operations such as navigation, file creation, and directory management.
*/
use std::io::{Error, ErrorKind, Read};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use flate2::read::GzDecoder;
use tar::Archive;

#[derive(Default, Copy, Clone, Debug)]
#[allow(dead_code)]
pub struct Inode {
    // File mode (type and permissions)
    pub(crate) i_mode: u16,
    // Lower 16 bits of user ID
    pub(crate) i_uid: u16,
    // Lower 32 bits of size in bytes
    pub(crate) i_size_lo: u32,
    // Last access time in seconds since epoch
    i_atime: u64,
    // Last inode change time
    i_ctime: u64,
    // Last data modification time
    pub(crate) i_mtime: u32,
    // Deletion time
    i_dtime: u32,
    // Lower 16 bits of group ID
    pub(crate) i_gid: u16,
    // Hard link count
    pub(crate) i_links_count: u16,
    // File flags
    i_flags: u32,
    // High 16 bits of user ID
    pub(crate) i_uid_high: u16,
    // High 16 bits of group ID
    pub(crate) i_gid_high: u16,
    // Extra modification time (nanoseconds)
    i_atime_extra: u32,
    // File creation time (seconds since epoch)
    i_crtime: u32,
    // File creation time (nanoseconds)
    i_crtime_extra: u32,
}

/// InodeData combines the inode metadata with the actual file content
#[derive(Clone, Debug)]
pub struct InodeData {
    pub inode: Inode,
    pub content: Option<FileContent>,
}

#[derive(Clone, Debug)]
pub struct DirEntry {
    /// Inode number that this directory entry points to
    pub inode_number: u64,

    /// Filename (variable length, not null-terminated, up to 255 bytes)
    /// Only the first name_len bytes are valid
    pub name: String,
}

/// A view of a file that combines directory entry info with inode data
/// This maintains API compatibility with the old DirEntry structure
#[derive(Clone, Debug)]
pub struct FileEntryView {
    pub name: String,
    pub inode: Inode,
    pub file_content: Option<FileContent>,
}

impl FileEntryView {
    fn from_parts(name: String, inode_data: &InodeData) -> Self {
        Self {
            name,
            inode: inode_data.inode,
            file_content: inode_data.content.clone(),
        }
    }
}


#[derive(Clone, Debug)]
pub enum FileContent {
    Directory(Vec<DirEntry>),
    RegularFile(Arc<Vec<u8>>),
    SymbolicLink(String),
}

#[derive(Debug)]
pub struct FileSystem {
    /// Inode number of the root directory
    root_inode: u64,

    /// Inode table: maps inode numbers to inode data
    inodes: HashMap<u64, InodeData>,

    /// Next available inode number
    next_inode: u64,

    /// Snapshot for rollback support
    snapshot: Option<FileSystemSnapshot>,

    // Device info
    #[allow(dead_code)]
    device: String,
}

#[derive(Clone, Debug)]
struct FileSystemSnapshot {
    inodes: HashMap<u64, InodeData>,
    next_inode: u64,
    root_inode: u64,
}

impl Default for FileSystem {
    fn default() -> Self {
        let mut inodes = HashMap::new();
        let root_inode_num = 1; // Root inode is always 1

        // Create root inode
        let root_inode_data = InodeData {
            inode: Inode::default(),
            content: Some(FileContent::Directory(Vec::with_capacity(20))),
        };

        inodes.insert(root_inode_num, root_inode_data);

        FileSystem {
            root_inode: root_inode_num,
            inodes,
            next_inode: 2, // Start allocating from inode 2
            snapshot: None,
            device: "/dev/sda1".to_string(),
        }
    }
}

impl FileSystem {
    /// Allocate a new inode number
    fn allocate_inode(&mut self) -> u64 {
        let inode_num = self.next_inode;
        self.next_inode += 1;
        inode_num
    }

    /// Get a reference to inode data
    fn get_inode(&self, inode_number: u64) -> std::io::Result<&InodeData> {
        self.inodes.get(&inode_number)
            .ok_or_else(|| Error::new(ErrorKind::NotFound, "Inode not found"))
    }

    /// Get a mutable reference to inode data
    fn get_inode_mut(&mut self, inode_number: u64) -> std::io::Result<&mut InodeData> {
        self.inodes.get_mut(&inode_number)
            .ok_or_else(|| Error::new(ErrorKind::NotFound, "Inode not found"))
    }

    pub fn resolve_absolute_path(&self, path: &str) -> String {
        // Ensure we have an absolute path
        if !path.starts_with('/') {
            return self.resolve_absolute_path(&format!("/{}", path));
        }

        // Split the path into segments
        let segments: Vec<&str> = path
            .split('/')
            .filter(|&segment| !segment.is_empty()) // Skip empty segments
            .collect();

        // Process each segment
        let mut resolved_segments: Vec<String> = Vec::new();

        for segment in segments {
            match segment {
                "." => {
                    // Current directory, do nothing
                }
                ".." => {
                    // Parent directory, remove the last segment if possible
                    resolved_segments.pop();
                }
                _ => {
                    // Normal segment, add to the path
                    resolved_segments.push(segment.to_string());
                }
            }
        }

        // Reconstruct the path
        if resolved_segments.is_empty() {
            "/".to_string() // Root directory
        } else {
            format!("/{}", resolved_segments.join("/"))
        }
    }

    /// Traverse a path to its inode, following intermediate symlinks.
    /// If `follow_final_symlink` is true, the final component's symlink is also resolved.
    fn resolve_to_inode(&self, path: &str, follow_final_symlink: bool) -> std::io::Result<u64> {
        let mut visited = HashSet::new();
        self.resolve_to_inode_inner(path, follow_final_symlink, &mut visited)
    }

    fn resolve_to_inode_inner(
        &self,
        path: &str,
        follow_final_symlink: bool,
        visited: &mut HashSet<String>,
    ) -> std::io::Result<u64> {
        let sanitized = self.resolve_absolute_path(path);

        if sanitized == "/" {
            return Ok(self.root_inode);
        }

        let components: Vec<&str> = sanitized
            .split('/')
            .filter(|s| !s.is_empty())
            .collect();

        let mut current_inode = self.root_inode;
        let mut current_path = String::new();

        for (i, component) in components.iter().enumerate() {
            // Follow symlinks on current_inode before component lookup (skip root)
            if i > 0 {
                current_inode =
                    self.resolve_symlink_at(current_inode, &current_path, visited)?;
            }

            let inode_data = self.get_inode(current_inode)?;
            match &inode_data.content {
                Some(FileContent::Directory(entries)) => {
                    let entry = entries
                        .iter()
                        .find(|e| e.name == *component)
                        .ok_or_else(|| {
                            Error::new(
                                ErrorKind::NotFound,
                                format!("Path component '{}' not found", component),
                            )
                        })?;
                    current_inode = entry.inode_number;
                    current_path = if current_path.is_empty() {
                        format!("/{}", component)
                    } else {
                        format!("{}/{}", current_path, component)
                    };
                }
                _ => return Err(Error::new(ErrorKind::Other, "Not a directory")),
            }
        }

        // Optionally follow symlinks on the final result
        if follow_final_symlink {
            current_inode = self.resolve_symlink_at(current_inode, &current_path, visited)?;
        }

        Ok(current_inode)
    }

    /// If the inode at `inode_num` is a symlink, resolve it to a non-symlink inode.
    fn resolve_symlink_at(
        &self,
        inode_num: u64,
        symlink_path: &str,
        visited: &mut HashSet<String>,
    ) -> std::io::Result<u64> {
        let inode_data = self.get_inode(inode_num)?;

        match &inode_data.content {
            Some(FileContent::SymbolicLink(target)) => {
                if !visited.insert(symlink_path.to_string()) {
                    return Err(Error::new(ErrorKind::Other, "Symbolic link cycle detected"));
                }

                let target_path = if target.starts_with('/') {
                    target.clone()
                } else {
                    let parent = symlink_path.rsplit_once('/').map(|(p, _)| p).unwrap_or("");
                    let parent = if parent.is_empty() { "/" } else { parent };
                    self.resolve_absolute_path(&format!("{}/{}", parent, target))
                };

                self.resolve_to_inode_inner(&target_path, true, visited)
            }
            _ => Ok(inode_num),
        }
    }

    /// Recursively deep-copy an inode subtree, returning the new root inode number.
    fn deep_copy_inode(&mut self, source_inode_num: u64) -> u64 {
        // Clone source data first to release the immutable borrow before mutating
        let source = match self.get_inode(source_inode_num) {
            Ok(d) => d.clone(),
            Err(_) => return self.allocate_inode(),
        };

        let new_inode_num = self.allocate_inode();

        let new_content = match source.content {
            Some(FileContent::Directory(entries)) => {
                let mut new_entries = Vec::with_capacity(entries.len());
                for entry in entries {
                    let child_new_inode = self.deep_copy_inode(entry.inode_number);
                    new_entries.push(DirEntry {
                        name: entry.name,
                        inode_number: child_new_inode,
                    });
                }
                Some(FileContent::Directory(new_entries))
            }
            Some(FileContent::RegularFile(data)) => Some(FileContent::RegularFile(data)),
            Some(FileContent::SymbolicLink(target)) => Some(FileContent::SymbolicLink(target)),
            None => None,
        };

        self.inodes.insert(
            new_inode_num,
            InodeData {
                inode: source.inode,
                content: new_content,
            },
        );

        new_inode_num
    }

    /// Free an inode and recursively free all children if it's a directory.
    /// Called after the directory entry has been removed and link count decremented to 0.
    fn free_inode_subtree(&mut self, inode_num: u64) {
        let children: Vec<u64> = {
            let inode_data = match self.inodes.get(&inode_num) {
                Some(d) => d,
                None => return,
            };
            match &inode_data.content {
                Some(FileContent::Directory(entries)) => {
                    entries.iter().map(|e| e.inode_number).collect()
                }
                _ => vec![],
            }
        };

        for child in children {
            let child_freed = {
                if let Some(child_data) = self.inodes.get_mut(&child) {
                    if child_data.inode.i_links_count > 0 {
                        child_data.inode.i_links_count -= 1;
                    }
                    child_data.inode.i_links_count == 0
                } else {
                    false
                }
            };
            if child_freed {
                self.free_inode_subtree(child);
            }
        }

        self.inodes.remove(&inode_num);
    }

    pub fn get_file(&self, path: &str) -> std::io::Result<FileEntryView> {
        let sanitized_path = self.resolve_absolute_path(path);

        if sanitized_path == "/" {
            let root_data = self.get_inode(self.root_inode)?;
            return Ok(FileEntryView::from_parts("/".to_string(), root_data));
        }

        let inode_num = self.resolve_to_inode(&sanitized_path, false)?;
        let inode_data = self.get_inode(inode_num)?;

        let components: Vec<&str> = sanitized_path
            .split('/')
            .filter(|s| !s.is_empty())
            .collect();
        let name = components.last().unwrap_or(&"/").to_string();
        Ok(FileEntryView::from_parts(name, inode_data))
    }

    pub fn get_file_mut(&mut self, path: &str) -> std::io::Result<&mut InodeData> {
        let sanitized_path = self.resolve_absolute_path(path);

        if sanitized_path == "/" {
            return self.get_inode_mut(self.root_inode);
        }

        let inode_num = self.resolve_to_inode(&sanitized_path, false)?;
        self.get_inode_mut(inode_num)
    }

    pub fn create_directory(&mut self, path: &str) -> std::io::Result<&mut InodeData> {
        let sanitized_path = self.resolve_absolute_path(path);

        if sanitized_path == "/" {
            return Err(Error::new(ErrorKind::InvalidInput, "File exists"));
        }

        let (parent_path, dir_name) = match sanitized_path.rsplit_once('/') {
            Some((parent, name)) => {
                let parent_path = if parent.is_empty() { "/" } else { parent };
                (parent_path.to_string(), name.to_string())
            }
            None => return Err(Error::new(ErrorKind::InvalidInput, "Invalid path")),
        };

        if dir_name.is_empty() {
            return Err(Error::new(ErrorKind::InvalidInput, "File exists"));
        }

        // Validate parent exists, is a directory, and entry doesn't already exist
        let parent_inode_num = {
            let p_inode = self.resolve_to_inode(&parent_path, true)?;
            let p_data = self.get_inode(p_inode)?;
            match &p_data.content {
                Some(FileContent::Directory(entries)) => {
                    if entries.iter().any(|e| e.name == dir_name) {
                        return Err(Error::new(
                            ErrorKind::AlreadyExists,
                            format!("Directory '{}' already exists", dir_name),
                        ));
                    }
                }
                _ => return Err(Error::new(ErrorKind::Other, "Parent is not a directory")),
            }
            p_inode
        };

        // Now safe to allocate and insert
        let new_inode_num = self.allocate_inode();
        let mut inode = Inode::default();
        inode.i_links_count = 1;
        self.inodes.insert(
            new_inode_num,
            InodeData {
                inode,
                content: Some(FileContent::Directory(Vec::new())),
            },
        );

        // Link into parent
        let parent_dir = self.get_inode_mut(parent_inode_num)?;
        match &mut parent_dir.content {
            Some(FileContent::Directory(entries)) => {
                entries.push(DirEntry {
                    name: dir_name,
                    inode_number: new_inode_num,
                });
                Ok(self.inodes.get_mut(&new_inode_num).unwrap())
            }
            _ => Err(Error::new(ErrorKind::Other, "Parent is not a directory")),
        }
    }

    pub fn create_file(&mut self, path: &str) -> std::io::Result<&mut InodeData> {
        let sanitized_path = self.resolve_absolute_path(path);

        let (parent_path, file_name) = match sanitized_path.rsplit_once('/') {
            Some((parent, name)) => {
                let parent_path = if parent.is_empty() { "/" } else { parent };
                (parent_path.to_string(), name.to_string())
            }
            None => return Err(Error::new(ErrorKind::InvalidInput, "Invalid path")),
        };

        if file_name.is_empty() {
            return Err(Error::new(ErrorKind::InvalidInput, "File name cannot be empty"));
        }

        // Validate parent exists, is a directory, and entry doesn't already exist
        let parent_inode_num = {
            let p_inode = self.resolve_to_inode(&parent_path, true)?;
            let p_data = self.get_inode(p_inode)?;
            match &p_data.content {
                Some(FileContent::Directory(entries)) => {
                    if entries.iter().any(|e| e.name == file_name) {
                        return Err(Error::new(
                            ErrorKind::AlreadyExists,
                            format!("File '{}' already exists", file_name),
                        ));
                    }
                }
                _ => return Err(Error::new(ErrorKind::Other, "Parent is not a directory")),
            }
            p_inode
        };

        // Now safe to allocate and insert
        let new_inode_num = self.allocate_inode();
        let mut inode = Inode::default();
        inode.i_links_count = 1;
        self.inodes.insert(
            new_inode_num,
            InodeData {
                inode,
                content: Some(FileContent::RegularFile(Arc::new(Vec::new()))),
            },
        );

        // Link into parent
        let parent_dir = self.get_inode_mut(parent_inode_num)?;
        match &mut parent_dir.content {
            Some(FileContent::Directory(entries)) => {
                entries.push(DirEntry {
                    name: file_name,
                    inode_number: new_inode_num,
                });
                Ok(self.inodes.get_mut(&new_inode_num).unwrap())
            }
            _ => Err(Error::new(ErrorKind::Other, "Parent is not a directory")),
        }
    }

    pub fn create_symlink(
        &mut self,
        link_path: &str,
        target_path: &str,
    ) -> std::io::Result<&mut InodeData> {
        let sanitized_link_path = self.resolve_absolute_path(link_path);

        let (parent_path, symlink_name) = match sanitized_link_path.rsplit_once('/') {
            Some((parent, name)) => {
                let parent_path = if parent.is_empty() { "/" } else { parent };
                (parent_path.to_string(), name.to_string())
            }
            None => return Err(Error::new(ErrorKind::InvalidInput, "Invalid path")),
        };

        if symlink_name.is_empty() {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                "Symlink name cannot be empty",
            ));
        }

        // Validate parent exists, is a directory, and entry doesn't already exist
        let parent_inode_num = {
            let p_inode = self.resolve_to_inode(&parent_path, true)?;
            let p_data = self.get_inode(p_inode)?;
            match &p_data.content {
                Some(FileContent::Directory(entries)) => {
                    if entries.iter().any(|e| e.name == symlink_name) {
                        return Err(Error::new(
                            ErrorKind::AlreadyExists,
                            format!("Entry '{}' already exists", symlink_name),
                        ));
                    }
                }
                _ => return Err(Error::new(ErrorKind::Other, "Parent is not a directory")),
            }
            p_inode
        };

        // Now safe to allocate and insert
        let new_inode_num = self.allocate_inode();
        let mut inode = Inode::default();
        inode.i_links_count = 1;
        self.inodes.insert(
            new_inode_num,
            InodeData {
                inode,
                content: Some(FileContent::SymbolicLink(target_path.to_string())),
            },
        );

        // Link into parent
        let parent_dir = self.get_inode_mut(parent_inode_num)?;
        match &mut parent_dir.content {
            Some(FileContent::Directory(entries)) => {
                entries.push(DirEntry {
                    name: symlink_name,
                    inode_number: new_inode_num,
                });
                Ok(self.inodes.get_mut(&new_inode_num).unwrap())
            }
            _ => Err(Error::new(ErrorKind::Other, "Parent is not a directory")),
        }
    }

    /// List directory contents as FileEntryView objects
    pub fn list_directory(&self, path: &str) -> std::io::Result<Vec<FileEntryView>> {
        let entry = self.follow_symlink(path)?;

        match &entry.file_content {
            Some(FileContent::Directory(entries)) => {
                let mut result = Vec::new();
                for dir_entry in entries {
                    if let Ok(inode_data) = self.get_inode(dir_entry.inode_number) {
                        result.push(FileEntryView::from_parts(
                            dir_entry.name.clone(),
                            inode_data,
                        ));
                    }
                }
                Ok(result)
            }
            _ => Err(Error::new(ErrorKind::Other, "Not a directory")),
        }
    }

    pub fn follow_symlink(&self, path: &str) -> std::io::Result<FileEntryView> {
        let mut current_path = self.resolve_absolute_path(path);
        let mut visited_paths = std::collections::HashSet::new();

        loop {
            let entry = self.get_file(&current_path)?;

            match &entry.file_content {
                Some(FileContent::SymbolicLink(target)) => {
                    // Detect cycles in symlinks
                    if !visited_paths.insert(current_path.clone()) {
                        return Err(Error::new(ErrorKind::Other, "Symbolic link cycle detected"));
                    }

                    // Update current path to follow the symlink
                    current_path = if target.starts_with('/') {
                        target.clone()
                    } else {
                        // Handle relative paths by combining with parent directory
                        let parent = current_path.rsplit_once('/').map(|(p, _)| p)
                            .unwrap_or("");
                        let parent = if parent.is_empty() { "/" } else { parent };
                        self.resolve_absolute_path(&format!("{}/{}", parent, target))
                    };
                },
                _ => return Ok(entry), // Found non-symlink entry
            }
        }
    }

    #[allow(dead_code)]
    pub fn copy_file(&mut self, source_path: &str, dest_path: &str) -> std::io::Result<()> {
        let sanitized_source = self.resolve_absolute_path(source_path);
        let sanitized_dest = self.resolve_absolute_path(dest_path);

        if sanitized_source == sanitized_dest {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                "Source and destination are the same",
            ));
        }

        // Check if destination already exists
        if self.get_file(&sanitized_dest).is_ok() {
            return Err(Error::new(ErrorKind::AlreadyExists, "Destination already exists"));
        }

        // Resolve source inode (follow symlinks)
        let source_inode_num = self.resolve_to_inode(&sanitized_source, true)?;

        // Deep-copy the source inode subtree (creates new inodes for all children)
        let new_inode_num = self.deep_copy_inode(source_inode_num);

        // Get destination parent directory and new name
        let (dest_parent_path, dest_name) = match sanitized_dest.rsplit_once('/') {
            Some((parent, name)) => {
                let parent_path = if parent.is_empty() { "/" } else { parent };
                (parent_path.to_string(), name.to_string())
            }
            None => return Err(Error::new(ErrorKind::InvalidInput, "Invalid destination path")),
        };

        // Add entry to destination parent
        let dest_parent_inode_num = self.resolve_to_inode(&dest_parent_path, true)?;
        let dest_parent = self.get_inode_mut(dest_parent_inode_num)?;
        match &mut dest_parent.content {
            Some(FileContent::Directory(entries)) => {
                entries.push(DirEntry {
                    name: dest_name,
                    inode_number: new_inode_num,
                });
                Ok(())
            }
            _ => Err(Error::new(
                ErrorKind::Other,
                "Destination parent is not a directory",
            )),
        }
    }

    #[allow(dead_code)]
    pub fn move_file(&mut self, source_path: &str, dest_path: &str) -> std::io::Result<()> {
        let sanitized_source = self.resolve_absolute_path(source_path);
        let sanitized_dest = self.resolve_absolute_path(dest_path);

        if sanitized_source == sanitized_dest {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                "Source and destination are the same",
            ));
        }

        if sanitized_source == "/" {
            return Err(Error::new(ErrorKind::InvalidInput, "Cannot move root directory"));
        }

        self.copy_file(&sanitized_source, &sanitized_dest)?;
        self.remove_file(&sanitized_source)?;

        Ok(())
    }

    /// Create a hard link to an existing file
    pub fn create_hard_link(&mut self, target_path: &str, link_path: &str) -> std::io::Result<()> {
        let sanitized_target = self.resolve_absolute_path(target_path);
        let sanitized_link = self.resolve_absolute_path(link_path);

        if sanitized_target == sanitized_link {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                "Target and link are the same",
            ));
        }

        if self.get_file(&sanitized_link).is_ok() {
            return Err(Error::new(ErrorKind::AlreadyExists, "Link path already exists"));
        }

        // Get target inode number (follow symlinks to the real target)
        let target_inode_num = self.resolve_to_inode(&sanitized_target, true)?;

        // Can't hard link to a directory
        {
            let target_inode_data = self.get_inode(target_inode_num)?;
            if matches!(target_inode_data.content, Some(FileContent::Directory(_))) {
                return Err(Error::new(
                    ErrorKind::InvalidInput,
                    "Cannot create hard link to directory",
                ));
            }
        }

        // Get link parent directory and name
        let (link_parent_path, link_name) = match sanitized_link.rsplit_once('/') {
            Some((parent, name)) => {
                let parent_path = if parent.is_empty() { "/" } else { parent };
                (parent_path.to_string(), name.to_string())
            }
            None => return Err(Error::new(ErrorKind::InvalidInput, "Invalid link path")),
        };

        // Add entry to parent directory
        let parent_inode_num = self.resolve_to_inode(&link_parent_path, true)?;
        let parent_dir = self.get_inode_mut(parent_inode_num)?;
        match &mut parent_dir.content {
            Some(FileContent::Directory(entries)) => {
                entries.push(DirEntry {
                    name: link_name,
                    inode_number: target_inode_num,
                });

                // Increment link count
                if let Some(inode_data) = self.inodes.get_mut(&target_inode_num) {
                    inode_data.inode.i_links_count += 1;
                }

                Ok(())
            }
            _ => Err(Error::new(ErrorKind::Other, "Parent is not a directory")),
        }
    }

    pub fn remove_file(&mut self, path: &str) -> std::io::Result<()> {
        let sanitized_path = self.resolve_absolute_path(path);

        if sanitized_path == "/" {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                "Cannot remove root directory",
            ));
        }

        let (parent_path, file_name) = match sanitized_path.rsplit_once('/') {
            Some((parent, name)) => {
                let parent_path = if parent.is_empty() { "/" } else { parent };
                (parent_path.to_string(), name.to_string())
            }
            None => return Err(Error::new(ErrorKind::InvalidInput, "Invalid path")),
        };

        // Resolve parent and remove the entry
        let parent_inode_num = self.resolve_to_inode(&parent_path, true)?;

        let entry_inode_num = {
            let parent_data = self.get_inode_mut(parent_inode_num)?;
            match &mut parent_data.content {
                Some(FileContent::Directory(entries)) => {
                    let entry_index = entries
                        .iter()
                        .position(|entry| entry.name == file_name)
                        .ok_or_else(|| {
                            Error::new(
                                ErrorKind::NotFound,
                                format!("File '{}' not found", file_name),
                            )
                        })?;
                    let inode_num = entries[entry_index].inode_number;
                    entries.remove(entry_index);
                    inode_num
                }
                _ => return Err(Error::new(ErrorKind::Other, "Parent is not a directory")),
            }
        };

        // Decrement link count
        let should_free = {
            let inode_data = self
                .inodes
                .get_mut(&entry_inode_num)
                .ok_or_else(|| Error::new(ErrorKind::NotFound, "Inode not found"))?;
            if inode_data.inode.i_links_count > 0 {
                inode_data.inode.i_links_count -= 1;
            }
            inode_data.inode.i_links_count == 0
        };

        // If fully unlinked, recursively free the inode (and children if directory)
        if should_free {
            self.free_inode_subtree(entry_inode_num);
        }

        Ok(())
    }

    pub fn process_targz<R: Read>(&mut self, reader: R) -> std::io::Result<()> {
        let gz_decoder = GzDecoder::new(reader);
        let mut archive = Archive::new(gz_decoder);

        for entry in archive.entries()? {
            let mut entry = entry?;
            let path = entry.path()?;
            let path_str = path.to_string_lossy().to_string();

            let header = entry.header();

            log::trace!(
                "Processing entry: {} Type: {:?} Size: {}",
                path_str,
                header.entry_type(),
                header.size().unwrap_or(0)
            );

            // Prepare common inode metadata from tar header
            let mut inode = Inode::default();
            inode.i_mode = header.mode()? as u16;

            let uid = header.uid()? as u32;
            inode.i_uid = (uid & 0xFFFF) as u16;
            inode.i_uid_high = ((uid >> 16) & 0xFFFF) as u16;

            let gid = header.gid()? as u32;
            inode.i_gid = (gid & 0xFFFF) as u16;
            inode.i_gid_high = ((gid >> 16) & 0xFFFF) as u16;

            if let Ok(mtime) = header.mtime() {
                inode.i_mtime = mtime as u32;
            }

            if let Some(gnu_header) = header.as_gnu() {
                if let Ok(atime) = gnu_header.atime() {
                    inode.i_atime = atime;
                }
                if let Ok(ctime) = gnu_header.ctime() {
                    inode.i_ctime = ctime;
                }
            }

            inode.i_size_lo = header.size()? as u32;
            inode.i_links_count = 1;

            if header.entry_type().is_dir() {
                match self.create_directory(&path_str) {
                    Ok(inode_data) => {
                        inode_data.inode = inode;
                    }
                    Err(err) => match err.kind() {
                        ErrorKind::AlreadyExists => {
                            log::trace!("Directory already exists: {}", path_str);
                            // Update metadata on existing directory
                            if let Ok(existing) = self.get_file_mut(&path_str) {
                                existing.inode = inode;
                            }
                        }
                        _ => {
                            log::warn!("Failed to create directory: {}: {}", path_str, err);
                        }
                    },
                }
            } else if header.entry_type().is_file() {
                let file_inode_data = self.create_file(&path_str)?;
                file_inode_data.inode = inode;

                let mut content = Vec::new();
                entry.read_to_end(&mut content)?;
                file_inode_data.inode.i_size_lo = content.len() as u32;
                file_inode_data.content = Some(FileContent::RegularFile(Arc::new(content)));
            } else if header.entry_type().is_symlink() {
                let target = entry
                    .link_name()?
                    .ok_or_else(|| Error::new(ErrorKind::Other, "Symbolic link target is missing"))?
                    .to_string_lossy()
                    .to_string();

                let symlink_inode_data = self.create_symlink(&path_str, &target)?;
                symlink_inode_data.inode = inode;
                symlink_inode_data.inode.i_size_lo = target.len() as u32;
            } else if header.entry_type().is_hard_link() {
                let target = entry
                    .link_name()?
                    .ok_or_else(|| Error::new(ErrorKind::Other, "Hard link target is missing"))?
                    .to_string_lossy()
                    .to_string();

                match self.create_hard_link(&target, &path_str) {
                    Ok(_) => {
                        log::trace!("Created hard link: {} -> {}", path_str, target);
                    }
                    Err(err) => {
                        log::warn!("Failed to create hard link {} -> {}: {}", path_str, target, err);
                    }
                }
            } else {
                log::warn!("Skipping unsupported entry type: {}", path_str);
            }
        }

        Ok(())
    }

    /// Take a snapshot of the current filesystem state for later rollback.
    /// With Arc-wrapped file content, this is cheap (Arc reference count bumps, not deep copies).
    pub fn take_snapshot(&mut self) {
        self.snapshot = Some(FileSystemSnapshot {
            inodes: self.inodes.clone(),
            next_inode: self.next_inode,
            root_inode: self.root_inode,
        });
        log::debug!("Filesystem snapshot taken ({} inodes)", self.inodes.len());
    }

    /// Restore the filesystem to the state captured by `take_snapshot`.
    pub fn restore_snapshot(&mut self) -> std::io::Result<()> {
        let snapshot = self
            .snapshot
            .as_ref()
            .ok_or_else(|| Error::new(ErrorKind::Other, "No snapshot available"))?;
        self.inodes = snapshot.inodes.clone();
        self.next_inode = snapshot.next_inode;
        self.root_inode = snapshot.root_inode;
        log::debug!("Filesystem restored from snapshot ({} inodes)", self.inodes.len());
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::ErrorKind;

    #[test]
    fn test_resolve_absolute_path_standard() {
        let fs = FileSystem::default();
        assert_eq!(fs.resolve_absolute_path("/"), "/");
        assert_eq!(fs.resolve_absolute_path("/home/user"), "/home/user");
    }

    #[test]
    fn test_resolve_absolute_path_relative() {
        let fs = FileSystem::default();
        assert_eq!(
            fs.resolve_absolute_path("/home/user/./documents"),
            "/home/user/documents"
        );
        assert_eq!(
            fs.resolve_absolute_path("/home/user/../admin"),
            "/home/admin"
        );
    }

    #[test]
    fn test_resolve_absolute_path_multiple_relative() {
        let fs = FileSystem::default();
        assert_eq!(
            fs.resolve_absolute_path("/home/./user/../../etc/passwd"),
            "/etc/passwd"
        );
    }

    #[test]
    fn test_resolve_absolute_path_beyond_root() {
        let fs = FileSystem::default();
        assert_eq!(fs.resolve_absolute_path("/home/../../../../"), "/");
    }

    #[test]
    fn test_resolve_absolute_path_mixed() {
        let fs = FileSystem::default();
        assert_eq!(
            fs.resolve_absolute_path("/./home//user/./docs/../files/./"),
            "/home/user/files"
        );
    }

    #[test]
    fn test_get_file_mut_root() {
        let mut fs = FileSystem::default();

        let result = fs.get_file_mut("/");
        assert!(result.is_ok());

        // Check that we got the root directory
        let root = result.unwrap();
        match root.content.as_ref().unwrap() {
            FileContent::Directory(_) => {}
            FileContent::RegularFile(_) => {
                assert!(false, "Root should be a directory");
            }
            FileContent::SymbolicLink(_) => {
                assert!(false, "Root should be a directory");
            }
        }
    }

    #[test]
    fn test_get_file_mut_nonexistent() {
        let mut fs = FileSystem::default();

        let result = fs.get_file_mut("/nonexistent");
        assert!(result.is_err());

        // Check error is NotFound
        let err = result.unwrap_err();
        assert_eq!(err.kind(), ErrorKind::NotFound);
    }

    #[test]
    fn test_get_file_mut_nested_path() {
        let mut fs = FileSystem::default();

        // Set up a directory structure using the API
        fs.create_directory("/home").unwrap();
        fs.create_directory("/home/user").unwrap();

        let result = fs.get_file_mut("/home/user");
        assert!(result.is_ok());

        // Check that we got the correct directory
        let dir = result.unwrap();
        match dir.content.as_ref() {
            None => {
                assert!(false, "Should be a directory");
            }
            Some(content) => {
                assert!(matches!(content, FileContent::Directory(_)));
            }
        }
    }

    #[test]
    fn test_create_directory_root() {
        let mut fs = FileSystem::default();

        let result = fs.create_directory("/");
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().kind(), ErrorKind::InvalidInput);
    }

    #[test]
    fn test_create_directory_simple() {
        let mut fs = FileSystem::default();

        let result = fs.create_directory("/documents");
        assert!(result.is_ok());

        // Verify the directory was created
        let dir = fs.get_file("/documents");
        assert!(dir.is_ok());
        assert_eq!(dir.unwrap().name, "documents");
    }

    #[test]
    fn test_create_directory_nested() {
        let mut fs = FileSystem::default();

        // First create parent directory
        let result1 = fs.create_directory("/home");
        assert!(result1.is_ok());

        // Now create nested directory
        let result2 = fs.create_directory("/home/user");
        assert!(result2.is_ok());

        // Verify the nested directory was created
        let dir = fs.get_file("/home/user");
        assert!(dir.is_ok());
        assert_eq!(dir.unwrap().name, "user");
    }

    #[test]
    fn test_create_directory_parent_missing() {
        let mut fs = FileSystem::default();

        // Try to create nested directory without parent
        let result = fs.create_directory("/home/user/documents");
        assert!(result.is_err());

        // Verify it's the right error
        let err = result.unwrap_err();
        assert_eq!(err.kind(), ErrorKind::NotFound);
    }

    #[test]
    fn test_create_directory_already_exists() {
        let mut fs = FileSystem::default();

        // Create directory
        let result1 = fs.create_directory("/documents");
        assert!(result1.is_ok());

        // Try to create it again
        let result2 = fs.create_directory("/documents");
        assert!(result2.is_err());

        // Verify it's the right error
        let err = result2.unwrap_err();
        assert_eq!(err.kind(), ErrorKind::AlreadyExists);
    }

    #[test]
    fn test_create_file_simple() {
        let mut fs = FileSystem::default();

        let result = fs.create_file("/hello.txt");
        assert!(result.is_ok());

        // Verify the file was created
        let file = fs.get_file("/hello.txt").unwrap();
        assert_eq!(file.name, "hello.txt");
        match file.file_content.as_ref() {
            None => {
                assert!(false, "hello.txt should be a file");
            }
            Some(content) => {
                assert!(matches!(content, FileContent::RegularFile(_)));
            }
        }
    }

    #[test]
    fn test_create_file_nested() {
        let mut fs = FileSystem::default();

        // First create parent directory
        let result1 = fs.create_directory("/home");
        assert!(result1.is_ok());

        // Now create file in that directory
        let result2 = fs.create_file("/home/config.txt");
        assert!(result2.is_ok());

        // Verify the file was created
        let file = fs.get_file("/home/config.txt").unwrap();
        assert_eq!(file.name, "config.txt");
        match file.file_content.as_ref() {
            None => {
                assert!(false, "config.txt should be a file");
            }
            Some(content) => {
                assert!(matches!(content, FileContent::RegularFile(_)));
            }
        }
    }

    #[test]
    fn test_create_file_parent_missing() {
        let mut fs = FileSystem::default();

        // Try to create file without parent directory
        let result = fs.create_file("/home/user/hello.txt");
        assert!(result.is_err());

        // Verify it's the right error
        let err = result.unwrap_err();
        assert_eq!(err.kind(), ErrorKind::NotFound);
    }

    #[test]
    fn test_create_file_already_exists() {
        let mut fs = FileSystem::default();

        // Create file
        let result1 = fs.create_file("/hello.txt");
        assert!(result1.is_ok());

        // Try to create it again
        let result2 = fs.create_file("/hello.txt");
        assert!(result2.is_err());

        // Verify it's the right error
        let err = result2.unwrap_err();
        assert_eq!(err.kind(), ErrorKind::AlreadyExists);
    }

    #[test]
    fn test_create_file_in_file() {
        let mut fs = FileSystem::default();

        // Create file
        let result1 = fs.create_file("/hello.txt");
        assert!(result1.is_ok());

        // Try to create file inside a file
        let result2 = fs.create_file("/hello.txt/bad.txt");
        assert!(result2.is_err());

        // Verify it's the right error
        let err = result2.unwrap_err();
        assert_eq!(err.kind(), ErrorKind::Other); // Or more specific error
    }

    #[test]
    fn test_create_symlink_simple() {
        let mut fs = FileSystem::default();

        // Create a file to link to
        let file_result = fs.create_file("/target.txt");
        assert!(file_result.is_ok());

        // Create a symlink to the file
        let symlink_result = fs.create_symlink("/link.txt", "/target.txt");
        assert!(symlink_result.is_ok());

        // Verify the symlink was created correctly
        let link = fs.get_file("/link.txt").unwrap();
        assert_eq!(link.name, "link.txt");
        match &link.file_content {
            Some(FileContent::SymbolicLink(target)) => {
                assert_eq!(target, "/target.txt");
            },
            _ => {
                assert!(false, "Should be a symbolic link");
            }
        }
    }

    #[test]
    fn test_create_symlink_nested() {
        let mut fs = FileSystem::default();

        // Create parent directory
        fs.create_directory("/home").unwrap();

        // Create a symlink in that directory
        let result = fs.create_symlink("/home/link.txt", "/etc/passwd");
        assert!(result.is_ok());

        // Verify the symlink was created
        let symlink = fs.get_file("/home/link.txt").unwrap();
        match &symlink.file_content {
            Some(FileContent::SymbolicLink(target)) => {
                assert_eq!(target, "/etc/passwd");
            },
            _ => {
                assert!(false, "Should be a symbolic link");
            }
        }
    }

    #[test]
    fn test_create_symlink_parent_missing() {
        let mut fs = FileSystem::default();

        // Try to create symlink without parent directory
        let result = fs.create_symlink("/nonexistent/link.txt", "/target.txt");
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().kind(), ErrorKind::NotFound);
    }

    #[test]
    fn test_create_symlink_already_exists() {
        let mut fs = FileSystem::default();

        // Create a file first
        fs.create_file("/existing.txt").unwrap();

        // Try to create a symlink with the same name
        let result = fs.create_symlink("/existing.txt", "/target.txt");
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().kind(), ErrorKind::AlreadyExists);
    }

    #[test]
    fn test_copy_file_simple() {
        let mut fs = FileSystem::default();

        // Create a test file
        fs.create_file("/test.txt").unwrap();
        let file = fs.get_file_mut("/test.txt").unwrap();
        if let Some(FileContent::RegularFile(ref mut data)) = file.content {
            *data = Arc::new(b"Hello, World!".to_vec());
        }

        // Copy the file
        let result = fs.copy_file("/test.txt", "/copy.txt");
        assert!(result.is_ok());

        // Verify both files exist and have same content
        let original = fs.get_file("/test.txt").unwrap();
        let copy = fs.get_file("/copy.txt").unwrap();

        match (&original.file_content, &copy.file_content) {
            (Some(FileContent::RegularFile(orig_data)), Some(FileContent::RegularFile(copy_data))) => {
                assert_eq!(orig_data, copy_data);
                assert_eq!(copy.name, "copy.txt");
            },
            _ => panic!("Files should be regular files"),
        }
    }

    #[test]
    fn test_copy_directory() {
        let mut fs = FileSystem::default();

        // Create directory structure
        fs.create_directory("/source").unwrap();
        fs.create_file("/source/file1.txt").unwrap();
        fs.create_file("/source/file2.txt").unwrap();

        // Copy the directory
        let result = fs.copy_file("/source", "/dest");
        assert!(result.is_ok());

        // Verify directory was copied
        let copy = fs.get_file("/dest").unwrap();
        assert_eq!(copy.name, "dest");
        match &copy.file_content {
            Some(FileContent::Directory(entries)) => {
                assert_eq!(entries.len(), 2);
                assert!(entries.iter().any(|e| e.name == "file1.txt"));
                assert!(entries.iter().any(|e| e.name == "file2.txt"));
            },
            _ => panic!("Should be a directory"),
        }
    }

    #[test]
    fn test_copy_file_already_exists() {
        let mut fs = FileSystem::default();

        fs.create_file("/source.txt").unwrap();
        fs.create_file("/dest.txt").unwrap();

        let result = fs.copy_file("/source.txt", "/dest.txt");
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().kind(), ErrorKind::AlreadyExists);
    }

    #[test]
    fn test_copy_file_to_itself() {
        let mut fs = FileSystem::default();

        fs.create_file("/test.txt").unwrap();

        let result = fs.copy_file("/test.txt", "/test.txt");
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().kind(), ErrorKind::InvalidInput);
    }

    #[test]
    fn test_move_file_simple() {
        let mut fs = FileSystem::default();

        // Create a test file
        fs.create_file("/source.txt").unwrap();

        // Move the file
        let result = fs.move_file("/source.txt", "/dest.txt");
        assert!(result.is_ok());

        // Verify source no longer exists
        let source_result = fs.get_file("/source.txt");
        assert!(source_result.is_err());
        assert_eq!(source_result.unwrap_err().kind(), ErrorKind::NotFound);

        // Verify destination exists
        let dest = fs.get_file("/dest.txt").unwrap();
        assert_eq!(dest.name, "dest.txt");
    }

    #[test]
    fn test_move_directory() {
        let mut fs = FileSystem::default();

        // Create directory with content
        fs.create_directory("/olddir").unwrap();
        fs.create_file("/olddir/file.txt").unwrap();

        // Move the directory
        let result = fs.move_file("/olddir", "/newdir");
        assert!(result.is_ok());

        // Verify source no longer exists
        assert!(fs.get_file("/olddir").is_err());

        // Verify destination exists with content
        let new_dir = fs.get_file("/newdir").unwrap();
        assert_eq!(new_dir.name, "newdir");
        match &new_dir.file_content {
            Some(FileContent::Directory(entries)) => {
                assert_eq!(entries.len(), 1);
                assert_eq!(entries[0].name, "file.txt");
            },
            _ => panic!("Should be a directory"),
        }
    }

    #[test]
    fn test_move_file_to_itself() {
        let mut fs = FileSystem::default();

        fs.create_file("/test.txt").unwrap();

        let result = fs.move_file("/test.txt", "/test.txt");
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().kind(), ErrorKind::InvalidInput);
    }

    #[test]
    fn test_move_root_directory() {
        let mut fs = FileSystem::default();

        let result = fs.move_file("/", "/newroot");
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().kind(), ErrorKind::InvalidInput);
    }

    #[test]
    fn test_remove_file_simple() {
        let mut fs = FileSystem::default();

        // Create a test file
        fs.create_file("/test.txt").unwrap();

        // Verify it exists
        assert!(fs.get_file("/test.txt").is_ok());

        // Remove the file
        let result = fs.remove_file("/test.txt");
        assert!(result.is_ok());

        // Verify it no longer exists
        let get_result = fs.get_file("/test.txt");
        assert!(get_result.is_err());
        assert_eq!(get_result.unwrap_err().kind(), ErrorKind::NotFound);
    }

    #[test]
    fn test_remove_directory() {
        let mut fs = FileSystem::default();

        // Create directory
        fs.create_directory("/testdir").unwrap();

        // Remove the directory
        let result = fs.remove_file("/testdir");
        assert!(result.is_ok());

        // Verify it no longer exists
        assert!(fs.get_file("/testdir").is_err());
    }

    #[test]
    fn test_remove_nonexistent_file() {
        let mut fs = FileSystem::default();

        let result = fs.remove_file("/nonexistent.txt");
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().kind(), ErrorKind::NotFound);
    }

    #[test]
    fn test_remove_root_directory() {
        let mut fs = FileSystem::default();

        let result = fs.remove_file("/");
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().kind(), ErrorKind::InvalidInput);
    }

    #[test]
    fn test_create_hard_link() {
        let mut fs = FileSystem::default();

        // Create a file with content
        fs.create_file("/original.txt").unwrap();
        let file = fs.get_file_mut("/original.txt").unwrap();
        if let Some(FileContent::RegularFile(ref mut data)) = file.content {
            *data = Arc::new(b"Hello, Hard Links!".to_vec());
        }

        // Create a hard link
        let result = fs.create_hard_link("/original.txt", "/link.txt");
        assert!(result.is_ok());

        // Verify both paths point to the same content
        let original = fs.get_file("/original.txt").unwrap();
        let link = fs.get_file("/link.txt").unwrap();

        match (&original.file_content, &link.file_content) {
            (Some(FileContent::RegularFile(orig_data)), Some(FileContent::RegularFile(link_data))) => {
                assert_eq!(orig_data, link_data);
                assert_eq!(orig_data.as_slice(), b"Hello, Hard Links!");
            },
            _ => panic!("Both should be regular files"),
        }

        // Verify link count
        assert_eq!(original.inode.i_links_count, 2);
        assert_eq!(link.inode.i_links_count, 2);
    }

    #[test]
    fn test_hard_link_modify_one_affects_both() {
        let mut fs = FileSystem::default();

        // Create file and hard link
        fs.create_file("/file1.txt").unwrap();
        fs.create_hard_link("/file1.txt", "/file2.txt").unwrap();

        // Modify via first path
        let file1 = fs.get_file_mut("/file1.txt").unwrap();
        if let Some(FileContent::RegularFile(ref mut data)) = file1.content {
            *data = Arc::new(b"Modified content".to_vec());
        }

        // Verify change visible through second path
        let file2 = fs.get_file("/file2.txt").unwrap();
        match &file2.file_content {
            Some(FileContent::RegularFile(data)) => {
                assert_eq!(data.as_slice(), b"Modified content");
            },
            _ => panic!("Should be a regular file"),
        }
    }

    #[test]
    fn test_hard_link_remove_one_keeps_other() {
        let mut fs = FileSystem::default();

        // Create file and hard link
        fs.create_file("/file1.txt").unwrap();
        let file = fs.get_file_mut("/file1.txt").unwrap();
        if let Some(FileContent::RegularFile(ref mut data)) = file.content {
            *data = Arc::new(b"Test data".to_vec());
        }
        fs.create_hard_link("/file1.txt", "/file2.txt").unwrap();

        // Remove first path
        fs.remove_file("/file1.txt").unwrap();

        // Verify second path still works
        let file2 = fs.get_file("/file2.txt").unwrap();
        match &file2.file_content {
            Some(FileContent::RegularFile(data)) => {
                assert_eq!(data.as_slice(), b"Test data");
            },
            _ => panic!("Should be a regular file"),
        }

        // Verify link count decreased
        assert_eq!(file2.inode.i_links_count, 1);
    }

    #[test]
    fn test_hard_link_cannot_link_directory() {
        let mut fs = FileSystem::default();

        fs.create_directory("/dir").unwrap();

        let result = fs.create_hard_link("/dir", "/dirlink");
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().kind(), ErrorKind::InvalidInput);
    }
}
