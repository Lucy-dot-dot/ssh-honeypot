use std::io::ErrorKind;
use chrono::{Local, TimeZone};
use crate::shell::filesystem::fs2::*;

/// Struct to represent ls command options
#[derive(Default)]
struct LsOptions {
    all: bool,               // -a: Include entries starting with .
    almost_all: bool,        // -A: Like -a but do not list . and ..
    long_format: bool,       // -l: Use long listing format
    human_readable: bool,    // -h: Print sizes in human readable format
    recursive: bool,         // -R: List subdirectories recursively
    size: bool,              // -s: Print size of each file
    sort_time: bool,         // -t: Sort by modification time, newest first
    sort_size: bool,         // -S: Sort by file size, largest first
    reverse: bool,           // -r: Reverse order while sorting
    one_per_line: bool,      // -1: List one file per line
    show_inode: bool,        // -i: Print the index number of each file
    classify: bool,          // -F: Append indicator (*/=>@|) to entries
    colorize: bool,          // --color: Colorize the output
    directory: bool,         // -d: List directories themselves, not their contents
}

/// Parse ls command to extract options and target path
fn parse_ls_command(cmd: &str) -> (LsOptions, String) {
    let mut options = LsOptions::default();
    let parts: Vec<&str> = cmd.split_whitespace().collect();

    // Skip the "ls" command itself
    let mut target_path = String::from(".");
    let mut i = 1;

    while i < parts.len() {
        let part = parts[i];

        if part.starts_with('-') {
            // Handle options
            if part.starts_with("--") {
                // Long options
                match part {
                    "--all" => options.all = true,
                    "--almost-all" => options.almost_all = true,
                    "--recursive" => options.recursive = true,
                    "--human-readable" => options.human_readable = true,
                    "--size" => options.size = true,
                    "--reverse" => options.reverse = true,
                    "--inode" => options.show_inode = true,
                    "--classify" => options.classify = true,
                    "--color" | "--color=always" => options.colorize = true,
                    "--directory" => options.directory = true,
                    _ => {} // Ignore unsupported options
                }
            } else {
                // Short options
                for c in part.chars().skip(1) {
                    match c {
                        'a' => options.all = true,
                        'A' => options.almost_all = true,
                        'l' => options.long_format = true,
                        'h' => options.human_readable = true,
                        'R' => options.recursive = true,
                        's' => options.size = true,
                        't' => options.sort_time = true,
                        'S' => options.sort_size = true,
                        'r' => options.reverse = true,
                        '1' => options.one_per_line = true,
                        'i' => options.show_inode = true,
                        'F' => options.classify = true,
                        'd' => options.directory = true,
                        _ => {} // Ignore unsupported options
                    }
                }
            }
        } else {
            // This is the target path
            target_path = part.to_string();
            break;
        }

        i += 1;
    }

    (options, target_path)
}

/// Format file size for display
fn format_size(size: u64, human_readable: bool) -> String {
    if !human_readable {
        return size.to_string();
    }

    const UNITS: [&str; 5] = ["B", "K", "M", "G", "T"];

    if size == 0 {
        return "0B".to_string();
    }

    let mut size_f = size as f64;
    let mut unit_index = 0;

    while size_f >= 1024.0 && unit_index < UNITS.len() - 1 {
        size_f /= 1024.0;
        unit_index += 1;
    }

    if size_f >= 10.0 {
        format!("{:.0}{}", size_f, UNITS[unit_index])
    } else {
        format!("{:.1}{}", size_f, UNITS[unit_index])
    }
}

/// Get permission string from inode mode
fn get_permission_string(mode: u16) -> String {
    let file_type = match mode & 0xF000 {
        0x4000 => 'd', // Directory
        0x8000 => '-', // Regular file
        0xA000 => 'l', // Symbolic link
        0x2000 => 'c', // Character device
        0x6000 => 'b', // Block device
        0x1000 => 'p', // FIFO
        0xC000 => 's', // Socket
        _ => '?',      // Unknown
    };

    let mut result = String::with_capacity(10);
    result.push(file_type);

    // Owner permissions
    result.push(if mode & 0x0100 != 0 { 'r' } else { '-' });
    result.push(if mode & 0x0080 != 0 { 'w' } else { '-' });
    result.push(if mode & 0x0040 != 0 {
        if mode & 0x0800 != 0 { 's' } else { 'x' }
    } else {
        if mode & 0x0800 != 0 { 'S' } else { '-' }
    });

    // Group permissions
    result.push(if mode & 0x0020 != 0 { 'r' } else { '-' });
    result.push(if mode & 0x0010 != 0 { 'w' } else { '-' });
    result.push(if mode & 0x0008 != 0 {
        if mode & 0x0400 != 0 { 's' } else { 'x' }
    } else {
        if mode & 0x0400 != 0 { 'S' } else { '-' }
    });

    // Other permissions
    result.push(if mode & 0x0004 != 0 { 'r' } else { '-' });
    result.push(if mode & 0x0002 != 0 { 'w' } else { '-' });
    result.push(if mode & 0x0001 != 0 {
        if mode & 0x0200 != 0 { 't' } else { 'x' }
    } else {
        if mode & 0x0200 != 0 { 'T' } else { '-' }
    });

    result
}

/// Get file type indicator for -F option
fn get_file_type_indicator(entry: &super::super::filesystem::fs2::DirEntry) -> char {
    match &entry.file_content {
        Some(FileContent::Directory(_)) => '/',
        Some(FileContent::RegularFile(_)) => {
            if entry.inode.i_mode & 0o111 != 0 {
                '*' // Executable
            } else {
                ' ' // Regular file
            }
        },
        Some(FileContent::SymbolicLink(_)) => '@',
        None => ' ',
    }
}

/// Format a timestamp from seconds since epoch
fn format_timestamp(timestamp: u32) -> String {
    let datetime = match Local.timestamp_opt(timestamp as i64, 0) {
        chrono::LocalResult::Single(dt) => dt,
        _ => Local::now(), // Fallback
    };

    let now = Local::now();
    let six_months_ago = now - chrono::Duration::days(180);

    // If the file is older than 6 months, show year instead of time
    if datetime < six_months_ago {
        datetime.format("%b %e  %Y").to_string()
    } else {
        datetime.format("%b %e %H:%M").to_string()
    }
}

/// Handle the ls command for the filesystem
pub fn handle_ls_command(cmd: &str, cwd: &str, fs: &FileSystem) -> String {
    let (options, target_path) = parse_ls_command(cmd);

    // Resolve path based on current directory
    let path = if target_path.starts_with('/') {
        target_path.clone()
    } else {
        format!("{}/{}", cwd, target_path)
    };

    let resolved_path = fs.resolve_absolute_path(&path);

    // Try to get the file/directory
    let entry = match fs.get_file(&resolved_path) {
        Ok(entry) => entry,
        Err(e) => return match e.kind() {
            ErrorKind::NotFound => {
                format!("ls: cannot access '{}': No such file or directory", target_path)
            }
            ErrorKind::PermissionDenied => {
                format!("ls: cannot access '{}': Permission denied", target_path)
            }
            _ => {
                format!("ls: cannot access '{}': {}", target_path, e)
            }
        },
    };

    let mut result = String::new();

    // Handle directory listing or single file display
    match &entry.file_content {
        Some(FileContent::Directory(entries)) => {
            // If -d is specified, just list the directory itself
            if options.directory {
                return format_entry(entry, &resolved_path, &options);
            }

            // Display directory content
            if options.recursive && !resolved_path.ends_with('/') && resolved_path != "/" {
                result.push_str(&format!("{}:\n", resolved_path));
            }

            let mut filtered_entries = entries.clone();

            // Filter hidden entries if needed
            if !options.all && !options.almost_all {
                filtered_entries.retain(|e| !e.name.starts_with('.'));
            }

            // Add . and .. for -a option but not for -A
            if options.all && !options.almost_all {
                // Add current directory (.)
                let mut dot_entry = entry.clone();
                dot_entry.name = ".".to_string();

                // Add parent directory (..)
                let parent_path = if resolved_path == "/" { "/" } else {
                    let parts: Vec<&str> = resolved_path.split('/').filter(|s| !s.is_empty()).collect();
                    if parts.is_empty() {
                        "/"
                    } else {
                        &*parts[..parts.len().saturating_sub(1)].join("/")
                    }
                };

                let parent_entry = match fs.get_file(&format!("/{}", parent_path)) {
                    Ok(entry) => {
                        let mut entry = entry.clone();
                        entry.name = "..".to_string();
                        entry
                    },
                    Err(_) => {
                        // If parent can't be retrieved, create a placeholder
                        let mut parent = entry.clone();
                        parent.name = "..".to_string();
                        parent
                    }
                };

                // Insert . and .. at the beginning
                filtered_entries.insert(0, dot_entry);
                filtered_entries.insert(1, parent_entry);
            }

            // Sort entries
            if options.sort_time {
                filtered_entries.sort_by(|a, b| b.inode.i_mtime.cmp(&a.inode.i_mtime));
            } else if options.sort_size {
                filtered_entries.sort_by(|a, b| {
                    let size_a = match &a.file_content {
                        Some(FileContent::RegularFile(data)) => data.len() as u32,
                        _ => a.inode.i_size_lo,
                    };

                    let size_b = match &b.file_content {
                        Some(FileContent::RegularFile(data)) => data.len() as u32,
                        _ => b.inode.i_size_lo,
                    };

                    size_b.cmp(&size_a)
                });
            } else {
                // Default: sort by name
                filtered_entries.sort_by(|a, b| a.name.cmp(&b.name));
            }

            // Apply reverse sorting if requested
            if options.reverse {
                filtered_entries.reverse();
            }

            // Format entries
            for entry in filtered_entries {
                let entry_path = if resolved_path == "/" {
                    format!("/{}", entry.name)
                } else {
                    format!("{}/{}", resolved_path, entry.name)
                };

                if options.long_format {
                    if !result.is_empty() {
                        result.push('\n');
                    }
                    result.push_str(&format_entry_long(&entry, &entry_path, &options));
                } else if options.one_per_line {
                    if !result.is_empty() {
                        result.push('\n');
                    }
                    result.push_str(&format_entry(&entry, &entry_path, &options));
                } else {
                    if !result.is_empty() {
                        result.push_str("  ");
                    }
                    result.push_str(&format_entry(&entry, &entry_path, &options));
                }
            }

            // Handle recursive listing
            if options.recursive {
                for entry in entries {
                    if let Some(FileContent::Directory(_)) = &entry.file_content {
                        if entry.name != "." && entry.name != ".." &&
                            (!entry.name.starts_with('.') || options.all || options.almost_all) {
                            let subdir_path = if resolved_path == "/" {
                                format!("/{}", entry.name)
                            } else {
                                format!("{}/{}", resolved_path, entry.name)
                            };

                            result.push_str("\n\n");
                            result.push_str(&handle_ls_command(
                                &format!("ls -R {}", subdir_path),
                                cwd,
                                fs
                            ));
                        }
                    }
                }
            }
        },
        _ => {
            // Single file entry
            result.push_str(&format_entry(entry, &resolved_path, &options));
        }
    }

    result
}

/// Format a single entry for display (non-long format)
fn format_entry(entry: &DirEntry, path: &str, options: &LsOptions) -> String {
    let mut result = String::new();

    // Show inode number if requested
    if options.show_inode {
        // Using a placeholder value that increments based on path to simulate inode numbers
        let inode_num = path.bytes().fold(0u32, |acc, b| acc.wrapping_add(b as u32));
        result.push_str(&format!("{:7} ", inode_num % 1000000));
    }

    // Show size if requested
    if options.size {
        let size = match &entry.file_content {
            Some(FileContent::RegularFile(data)) => data.len() as u64,
            _ => entry.inode.i_size_lo as u64,
        };

        result.push_str(&format!("{:4} ", format_size(size / 1024 + if size % 1024 > 0 { 1 } else { 0 }, options.human_readable)));
    }

    // File name with potential indicator
    let mut name = entry.name.clone();
    if options.classify {
        name.push(get_file_type_indicator(entry));
    }

    // Add colors if enabled
    if options.colorize {
        name = colorize_name(entry, name);
    }

    result.push_str(&name);
    result
}

/// Format entry in long format
fn format_entry_long(entry: &DirEntry, path: &str, options: &LsOptions) -> String {
    let mut result = String::new();

    // Show inode number if requested
    if options.show_inode {
        let inode_num = path.bytes().fold(0u32, |acc, b| acc.wrapping_add(b as u32));
        result.push_str(&format!("{:7} ", inode_num % 1000000));
    }

    // File type and permissions
    let perm_str = get_permission_string(entry.inode.i_mode);
    result.push_str(&format!("{} ", perm_str));

    // Link count
    result.push_str(&format!("{:2} ", entry.inode.i_links_count));

    // User and group
    let uid = ((entry.inode.i_uid_high as u32) << 16) | (entry.inode.i_uid as u32);
    let gid = ((entry.inode.i_gid_high as u32) << 16) | (entry.inode.i_gid as u32);

    // Map some common UIDs/GIDs to names for realism
    let username = match uid {
        0 => "root",
        1000 => "user",
        33 => "www-data",
        _ => "user",
    };

    let groupname = match gid {
        0 => "root",
        1000 => "user",
        33 => "www-data",
        _ => "user",
    };

    result.push_str(&format!("{:8} {:8} ", username, groupname));

    // File size
    let size = match &entry.file_content {
        Some(FileContent::RegularFile(data)) => data.len() as u64,
        Some(FileContent::SymbolicLink(_)) => entry.inode.i_size_lo as u64,
        _ => entry.inode.i_size_lo as u64,
    };

    result.push_str(&format!("{:>5} ", format_size(size, options.human_readable)));

    // Modification time
    result.push_str(&format!("{} ", format_timestamp(entry.inode.i_mtime)));

    // File name with potential indicator
    let mut name = entry.name.clone();
    if options.classify {
        name.push(get_file_type_indicator(entry));
    }

    // Add colors if enabled
    if options.colorize {
        name = colorize_name(entry, name);
    }

    // For symbolic links, show the target
    if let Some(FileContent::SymbolicLink(target)) = &entry.file_content {
        result.push_str(&format!("{} -> {}", name, target));
    } else {
        result.push_str(&name);
    }

    result
}

/// Add ANSI color codes to filenames based on file type
fn colorize_name(entry: &DirEntry, name: String) -> String {
    match &entry.file_content {
        Some(FileContent::Directory(_)) =>
            format!("\x1b[1;34m{}\x1b[0m", name), // Bold blue for directories
        Some(FileContent::RegularFile(_)) =>
            if entry.inode.i_mode & 0o111 != 0 {
                format!("\x1b[1;32m{}\x1b[0m", name) // Bold green for executables
            } else {
                name // Default for regular files
            },
        Some(FileContent::SymbolicLink(_)) =>
            format!("\x1b[1;36m{}\x1b[0m", name), // Bold cyan for symlinks
        None => name,
    }
}