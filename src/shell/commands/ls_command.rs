use async_trait::async_trait;
use super::command_trait::{Command, CommandResult};
use super::context::CommandContext;
use crate::shell::filesystem::fs2::FileContent;

/// LS command implementation using the new trait system
pub struct LsCommand;

#[async_trait]
impl Command for LsCommand {
    fn name(&self) -> &'static str {
        "ls"
    }
    
    fn aliases(&self) -> Vec<&'static str> {
        vec!["ll", "la"]
    }
    
    fn help(&self) -> String {
        "Usage: ls [OPTION]... [FILE]...\n\
        List information about the FILEs (the current directory by default).\n\
        Sort entries alphabetically if none of -cftuvSUX nor --sort is specified.\n\
        \n\
        -a, --all                  do not ignore entries starting with .\n\
        -A, --almost-all           do not list implied . and ..\n\
        -l                         use a long listing format\n\
        -h, --human-readable       with -l and/or -s, print human readable sizes\n\
        -r, --reverse              reverse order while sorting\n\
        -t                         sort by modification time, newest first\n\
        -S                         sort by file size, largest first\n\
        -1                         list one file per line\n\
        --help                     display this help and exit\n\
        --version                  output version information and exit\n".to_string()
    }
    
    fn version(&self) -> String {
        "ls (GNU coreutils) 8.32\n\
        License GPLv3+: GNU GPL version 3 or later <https://gnu.org/licenses/gpl.html>.\n\
        This is free software: you are free to change and redistribute it.\n\
        There is NO WARRANTY, to the extent permitted by law.\n".to_string()
    }
    
    async fn execute(&self, args: &str, context: &mut CommandContext) -> CommandResult {
        // Handle help and version flags
        if args.contains("--help") {
            return Ok(self.help());
        }
        
        if args.contains("--version") {
            return Ok(self.version());
        }
        
        let fs = context.filesystem.read().await;
        
        // Parse arguments
        let path = &context.cwd;
        let mut show_all = false;
        let mut long_format = false;
        let mut one_per_line = false;
        
        // Simple argument parsing
        let parts: Vec<&str> = args.split_whitespace().collect();
        let mut target_path = None;
        
        for part in parts {
            match part {
                "-a" | "--all" => show_all = true,
                "-l" => long_format = true,
                "-1" => one_per_line = true,
                "-la" | "-al" => {
                    show_all = true;
                    long_format = true;
                },
                arg if !arg.starts_with('-') => {
                    target_path = Some(arg);
                }
                _ => {} // Ignore other flags for simplicity
            }
        }
        
        // Determine the directory to list
        let list_path = if let Some(target) = target_path {
            if target.starts_with('/') {
                target.to_string()
            } else {
                format!("{}/{}", path.trim_end_matches('/'), target)
            }
        } else {
            path.to_string()
        };
        
        match fs.list_directory(&list_path) {
            Ok(entries) => {
                let mut result = String::new();

                // Filter entries based on show_all flag
                let filtered_entries: Vec<_> = entries.iter()
                    .filter(|entry| show_all || !entry.name.starts_with('.'))
                    .collect();

                if long_format {
                    // Long format listing
                    if show_all || !filtered_entries.is_empty() {
                        result.push_str(&format!("total {}\r\n", filtered_entries.len()));
                    }

                    for entry in filtered_entries {
                        let (permissions, size, _file_type) = match &entry.file_content {
                            Some(FileContent::Directory(_)) => ("drwxr-xr-x", 4096, "dir"),
                            Some(FileContent::RegularFile(data)) => ("-rw-r--r--", data.len(), "file"),
                            Some(FileContent::SymbolicLink(_)) => ("lrwxrwxrwx", 0, "link"),
                            None => ("?---------", 0, "unknown"),
                        };

                        result.push_str(&format!(
                            "{} 1 user user {:>8} Jan 01 12:00 {}\r\n",
                            permissions, size, entry.name
                        ));
                    }
                } else if one_per_line {
                    // One file per line
                    for entry in filtered_entries {
                        result.push_str(&format!("{}\r\n", entry.name));
                    }
                } else {
                    // Default format (multiple columns)
                    let names: Vec<&str> = filtered_entries.iter().map(|entry| entry.name.as_str()).collect();
                    if names.is_empty() {
                        // Empty directory
                    } else {
                        result.push_str(&names.join("  "));
                        result.push_str("\r\n");
                    }
                }

                Ok(result)
            },
            Err(_) => {
                // Try to check if it's a file instead
                match fs.follow_symlink(&list_path) {
                    Ok(entry) => {
                        match &entry.file_content {
                            Some(FileContent::RegularFile(_)) => {
                                // If it's a file, just show the filename
                                let filename = list_path.split('/').last().unwrap_or(&list_path);
                                Ok(format!("{}\r\n", filename))
                            },
                            Some(FileContent::SymbolicLink(_)) => {
                                Ok(format!("ls: cannot access '{}': symbolic link\r\n", list_path))
                            },
                            _ => {
                                Ok(format!("ls: cannot access '{}': No such file or directory\r\n", list_path))
                            }
                        }
                    },
                    Err(_) => {
                        Ok(format!("ls: cannot access '{}': No such file or directory\r\n", list_path))
                    }
                }
            }
        }
    }
}