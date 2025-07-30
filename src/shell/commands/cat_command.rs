use async_trait::async_trait;
use super::command_trait::{Command, CommandResult};
use super::context::CommandContext;
use crate::shell::filesystem::fs2::FileContent;

/// Cat command implementation using the new trait system
pub struct CatCommand;

#[async_trait]
impl Command for CatCommand {
    fn name(&self) -> &'static str {
        "cat"
    }
    
    fn help(&self) -> String {
        "Usage: cat [OPTION]... [FILE]...\n\
        Concatenate FILE(s) to standard output.\n\
        \n\
        With no FILE, or when FILE is -, read standard input.\n\
        \n\
        -A, --show-all           equivalent to -vET\n\
        -b, --number-nonblank    number nonempty output lines, overrides -n\n\
        -e                       equivalent to -vE\n\
        -E, --show-ends          display $ at end of each line\n\
        -n, --number             number all output lines\n\
        -s, --squeeze-blank      suppress repeated empty output lines\n\
        -t                       equivalent to -vT\n\
        -T, --show-tabs          display TAB characters as ^I\n\
        -u                       (ignored)\n\
        -v, --show-nonprinting   use ^ and M- notation, except for LFD and TAB\n\
        --help                   display this help and exit\n\
        --version                output version information and exit\n".to_string()
    }
    
    fn version(&self) -> String {
        "cat (GNU coreutils) 8.32\n\
        License GPLv3+: GNU GPL version 3 or later <https://gnu.org/licenses/gpl.html>.\n\
        This is free software: you are free to change and redistribute it.\n\
        There is NO WARRANTY, to the extent permitted by law.\n".to_string()
    }
    
    async fn execute(&self, args: &str, context: &mut CommandContext) -> CommandResult {
        let args = args.trim();
        
        // Handle help and version flags
        if args == "--help" {
            return Ok(self.help());
        }
        
        if args == "--version" {
            return Ok(self.version());
        }
        
        // If no arguments, simulate reading from stdin (but we'll just show a message)
        if args.is_empty() {
            return Ok("cat: reading from stdin not supported in honeypot\r\n".to_string());
        }
        
        // Parse file path (simple implementation - just take the first argument)
        let file_path = args.split_whitespace().next().unwrap_or("");
        
        if file_path.is_empty() {
            return Ok("cat: missing file operand\r\nTry 'cat --help' for more information.\r\n".to_string());
        }
        
        // Get filesystem and read file
        let fs = context.filesystem.read().await;
        
        match fs.follow_symlink(file_path) {
            Ok(entry) => {
                match entry.file_content {
                    None => {
                        Ok(format!("cat: {}: No such file or directory\r\n", file_path))
                    },
                    Some(ref content) => {
                        match content {
                            FileContent::Directory(_) => {
                                Ok(format!("cat: {}: Is a directory\r\n", file_path))
                            }
                            FileContent::RegularFile(bytes) => {
                                // Convert bytes to string safely
                                match String::from_utf8(bytes.clone()) {
                                    Ok(content) => Ok(content),
                                    Err(_) => {
                                        // If it's not valid UTF-8, show a binary file message
                                        Ok(format!("cat: {}: binary file\r\n", file_path))
                                    }
                                }
                            },
                            FileContent::SymbolicLink(_) => {
                                // This shouldn't happen since we resolved the symlink
                                Ok(format!("cat: {}: Is a symbolic link\r\n", file_path))
                            }
                        }
                    }
                }
            },
            Err(_) => Ok(format!("cat: {}: No such file or directory\r\n", file_path))
        }
    }
}