/*!
This module implements a simple, in-memory file system with `FileSystem`, `DirEntry`, and `Inode` structs to simulate hierarchical storage and operations critical to a file system. The code provides features like path resolution, creating files/directories, and retrieving directory or file entries using structured interfaces.

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
use flate2::read::GzDecoder;
use tar::Archive;

#[derive(Default, Copy, Clone, Debug)]
#[allow(dead_code)]
pub struct Inode {
    // File mode (type and permissions)
    i_mode: u16,
    // Lower 16 bits of user ID
    i_uid: u16,
    // Lower 32 bits of size in bytes
    i_size_lo: u32,
    // Last access time in seconds since epoch
    i_atime: u32,
    // Last inode change time
    i_ctime: u32,
    // Last data modification time
    i_mtime: u32,
    // Deletion time
    i_dtime: u32,
    // Lower 16 bits of group ID
    i_gid: u16,
    // Hard link count
    i_links_count: u16,
    // File flags
    i_flags: u32,
    // High 16 bits of user ID
    i_uid_high: u16,
    // High 16 bits of group ID
    i_gid_high: u16,
    // Extra modification time (nanoseconds)
    i_atime_extra: u32,
    // File creation time (seconds since epoch)
    i_crtime: u32,
    // File creation time (nanoseconds)
    i_crtime_extra: u32,
}

#[derive(Default, Clone, Debug)]
pub struct DirEntry {
    /// Inode number of the file
    #[allow(dead_code)]
    pub inode: Inode,

    /// I will store it right here for constant access times without searching
    pub file_content: Option<FileContent>,

    /// Filename (variable length, not null-terminated, up to 255 bytes)
    /// Only the first name_len bytes are valid
    pub name: String, // In reality, this is variable length based on name_len
}


#[derive(Clone, Debug)]
pub enum FileContent {
    Directory(Vec<DirEntry>),
    RegularFile(Vec<u8>),
    SymbolicLink(String),
}

#[derive(Debug)]
pub struct FileSystem {
    root: DirEntry,

    // Device info
    device: String,
}

impl Default for FileSystem {
    fn default() -> Self {
        let fs = FileSystem {
            root: DirEntry {
                name: "/".to_string(),
                file_content: Some(FileContent::Directory(Vec::with_capacity(20))),
                inode: Inode::default(),
            },
            device: "/dev/sda1".to_string(),
        };

        fs
    }
}

impl FileSystem {
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

    pub fn get_file(&self, path: &str) -> std::io::Result<&DirEntry> {
        let sanitized_path = self.resolve_absolute_path(path);
        // Handle root path special case
        if sanitized_path == "/" {
            // Find the root directory entry using the root_inode
            return Ok(&self.root);
        }

        // Get path components
        let components: Vec<&str> = sanitized_path
            .split('/')
            .filter(|&segment| !segment.is_empty())
            .collect();

        // Start with root directory
        let mut current_dir = &self.root;

        // Traverse the path
        for component in components {
            if let Some(FileContent::Directory(entries)) = &current_dir.file_content {
                // Find the matching entry in the current directory
                current_dir = entries
                    .iter()
                    .find(|entry| entry.name == component)
                    .ok_or_else(|| {
                        Error::new(
                            ErrorKind::NotFound,
                            format!("Path component '{}' not found", component),
                        )
                    })?;
            } else {
                return Err(Error::new(ErrorKind::Other, "Not a directory"));
            }
        }

        Ok(current_dir)
    }

    pub fn get_file_mut(&mut self, path: &str) -> std::io::Result<&mut DirEntry> {
        let sanitized_path = self.resolve_absolute_path(path);

        // Handle root path
        if sanitized_path == "/" {
            return Ok(&mut self.root);
        }

        let components: Vec<String> = sanitized_path
            .split('/')
            .filter(|&segment| !segment.is_empty())
            .map(|s| s.to_string())
            .collect();

        let mut current = &mut self.root;

        for component in components {
            // We need to find the child with name matching component
            match &mut current.file_content {
                Some(FileContent::Directory(entries)) => {
                    let entry_index = entries
                        .iter()
                        .position(|entry| entry.name == component)
                        .ok_or_else(|| {
                            Error::new(
                                ErrorKind::NotFound,
                                format!("Path component '{}' not found", component),
                            )
                        })?;

                    // This is the tricky part - we need to get a mutable reference to
                    // the specific child from entries
                    current = &mut entries[entry_index];
                }
                _ => return Err(Error::new(ErrorKind::Other, "Not a directory")),
            }
        }

        Ok(current)
    }

    pub fn create_directory(&mut self, path: &str) -> std::io::Result<()> {
        let sanitized_path = self.resolve_absolute_path(path);

        // Root directory always exists
        if sanitized_path == "/" {
            return Ok(())
        }

        // Get the parent directory path and new directory name
        let (parent_path, dir_name) = match sanitized_path.rsplit_once('/') {
            Some((parent, name)) => {
                let parent_path = if parent.is_empty() { "/" } else { parent };
                (parent_path, name)
            },
            None => return Err(Error::new(ErrorKind::InvalidInput, "Invalid path")),
        };

        // If dir_name is empty, this is the root directory
        if dir_name.is_empty() {
            return Ok(());
        }

        // Find the parent directory
        let parent_dir = self.get_file_mut(parent_path)?;

        // Make sure the parent is a directory
        match &mut parent_dir.file_content {
            Some(FileContent::Directory(entries)) => {
                // Check if directory already exists
                if entries.iter().any(|e| e.name == dir_name) {
                    return Err(Error::new(ErrorKind::AlreadyExists,
                                          format!("Directory '{}' already exists", dir_name)));
                }

                // Create the new directory entry
                entries.push(DirEntry {
                    name: dir_name.to_string(),
                    file_content: Some(FileContent::Directory(Vec::new())),
                    ..Default::default()
                });

                Ok(())
            },
            _ => Err(Error::new(ErrorKind::Other, "Parent is not a directory")),
        }
    }

    pub fn create_file(&mut self, path: &str) -> std::io::Result<&mut DirEntry> {
        let sanitized_path = self.resolve_absolute_path(path);

        // Get the parent directory path and file name
        let (parent_path, file_name) = match sanitized_path.rsplit_once('/') {
            Some((parent, name)) => {
                let parent_path = if parent.is_empty() { "/" } else { parent };
                (parent_path, name)
            },
            None => return Err(Error::new(ErrorKind::InvalidInput, "Invalid path")),
        };

        // File name cannot be empty
        if file_name.is_empty() {
            return Err(Error::new(ErrorKind::InvalidInput, "File name cannot be empty"));
        }

        // Find the parent directory
        let parent_dir = self.get_file_mut(parent_path)?;

        // Make sure the parent is a directory
        match &mut parent_dir.file_content {
            Some(FileContent::Directory(entries)) => {
                // Check if file already exists
                if entries.iter().any(|e| e.name == file_name) {
                    return Err(Error::new(ErrorKind::AlreadyExists,
                                          format!("File '{}' already exists", file_name)));
                }

                // Create the new file entry
                entries.push(DirEntry {
                    name: file_name.to_string(),
                    file_content: Some(FileContent::RegularFile(Vec::new())),
                    ..Default::default()
                });

                // Return a mutable reference to the newly created file
                // Note: this is tricky because we need to find it after adding it
                if let Some(index) = entries.iter().position(|e| e.name == file_name) {
                    Ok(&mut entries[index])
                } else {
                    // This should never happen, but just in case
                    Err(Error::new(ErrorKind::Other, "Failed to retrieve created file"))
                }
            },
            _ => Err(Error::new(ErrorKind::Other, "Parent is not a directory")),
        }
    }

    pub fn create_symlink(&mut self, link_path: &str, target_path: &str) -> std::io::Result<&mut DirEntry> {
        let sanitized_link_path = self.resolve_absolute_path(link_path);

        // Get the parent directory path and symlink name
        let (parent_path, symlink_name) = match sanitized_link_path.rsplit_once('/') {
            Some((parent, name)) => {
                let parent_path = if parent.is_empty() { "/" } else { parent };
                (parent_path, name)
            },
            None => return Err(Error::new(ErrorKind::InvalidInput, "Invalid path")),
        };

        // Symlink name cannot be empty
        if symlink_name.is_empty() {
            return Err(Error::new(ErrorKind::InvalidInput, "Symlink name cannot be empty"));
        }

        // Find the parent directory
        let parent_dir = self.get_file_mut(parent_path)?;

        // Make sure the parent is a directory
        match &mut parent_dir.file_content {
            Some(FileContent::Directory(entries)) => {
                // Check if symlink already exists
                if entries.iter().any(|e| e.name == symlink_name) {
                    return Err(Error::new(ErrorKind::AlreadyExists,
                                          format!("Entry '{}' already exists", symlink_name)));
                }

                // Create the new symlink entry
                entries.push(DirEntry {
                    name: symlink_name.to_string(),
                    file_content: Some(FileContent::SymbolicLink(target_path.to_string())),
                    ..Default::default()
                });

                // Return a mutable reference to the newly created symlink
                if let Some(index) = entries.iter().position(|e| e.name == symlink_name) {
                    Ok(&mut entries[index])
                } else {
                    // This should never happen, but just in case
                    Err(Error::new(ErrorKind::Other, "Failed to retrieve created symlink"))
                }
            },
            _ => Err(Error::new(ErrorKind::Other, "Parent is not a directory")),
        }
    }

    pub fn follow_symlink(&self, path: &str) -> std::io::Result<&DirEntry> {
        let mut current_path = self.resolve_absolute_path(path);
        let mut visited_paths = std::collections::HashSet::new();

        while let Ok(entry) = self.get_file(&current_path) {
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

        Err(Error::new(ErrorKind::NotFound, "Target not found"))
    }

    pub fn process_targz<R: Read>(&mut self, reader: R) -> std::io::Result<()> {
        let gz_decoder = GzDecoder::new(reader);
        let mut archive = Archive::new(gz_decoder);

        for entry in archive.entries()? {
            let mut entry = entry?;
            log::trace!("Processing entry: {}", entry.path()?.display());
            let path = entry.path()?;
            let path_str = path.to_string_lossy().to_string();

            if entry.header().entry_type().is_dir() {
                self.create_directory(&path_str)?;
            } else if entry.header().entry_type().is_file() {
                let file_entry = self.create_file(&path_str)?;

                let mut content = Vec::new();
                entry.read_to_end(&mut content)?;

                if let Some(FileContent::RegularFile(ref mut data)) = file_entry.file_content {
                    *data = content;
                }
            } else if entry.header().entry_type().is_symlink() {
                // Handle symbolic links
                let link_name = path_str;
                let target = entry.link_name()?.ok_or_else(|| {
                    Error::new(ErrorKind::Other, "Symbolic link target is missing")
                })?.to_string_lossy().to_string();

                self.create_symlink(&link_name, &target)?;
            }
            // Handle other types as needed
        }

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
        assert_eq!(root.name, "/");
        match root.file_content.as_ref().unwrap() {
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

        // Set up a directory structure
        if let Some(FileContent::Directory(ref mut entries)) = fs.root.file_content {
            entries.push(DirEntry {
                name: String::from("home"),
                file_content: Some(FileContent::Directory(vec![DirEntry {
                    name: String::from("user"),
                    file_content: Some(FileContent::Directory(Vec::new())),
                    ..Default::default()
                }])),
                ..Default::default()
            });
        }

        let result = fs.get_file_mut("/home/user");
        assert!(result.is_ok());

        // Check that we got the correct directory
        let dir = result.unwrap();
        assert_eq!(dir.name, "user");
        match dir.file_content.as_ref() {
            None => {
                assert!(false, "Root should be a directory");
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
        assert!(result.is_ok());
    }

    #[test]
    fn test_create_directory_simple() {
        let mut fs = FileSystem::default();

        let result = fs.create_directory("/documents");
        assert!(result.is_ok());

        // Verify the directory was created
        let dir = fs.get_file_mut("/documents");
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
        let dir = fs.get_file_mut("/home/user");
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
        let file = result.unwrap();
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
        let file = result2.unwrap();
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
        let link = symlink_result.unwrap();
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
}
