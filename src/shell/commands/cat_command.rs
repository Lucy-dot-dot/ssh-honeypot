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

    async fn execute(&self, args: &[String], context: &mut CommandContext) -> CommandResult {
        if args.iter().any(|a| a == "--help") {
            return Ok(self.help());
        }

        if args.iter().any(|a| a == "--version") {
            return Ok(self.version());
        }

        let files: Vec<&String> = args.iter().filter(|a| !a.starts_with('-')).collect();

        if files.is_empty() {
            return Ok("cat: reading from stdin not supported in honeypot\r\n".to_string());
        }

        let mut output = String::new();
        let mut errors = String::new();
        let fs = context.filesystem.read().await;

        for file_path in files {
            match fs.follow_symlink(file_path) {
                Ok(entry) => match &entry.file_content {
                    None => {
                        errors.push_str(&format!("cat: {}: No such file or directory\r\n", file_path));
                    }
                    Some(FileContent::Directory(_)) => {
                        errors.push_str(&format!("cat: {}: Is a directory\r\n", file_path));
                    }
                    Some(FileContent::RegularFile(bytes)) => {
                        let content = String::from_utf8_lossy(bytes);
                        output.push_str(&content.replace("\r\n", "\n").replace('\n', "\r\n"));
                    }
                    Some(FileContent::SymbolicLink(_)) => {
                        errors.push_str(&format!("cat: {}: Is a symbolic link\r\n", file_path));
                    }
                },
                Err(_) => {
                    errors.push_str(&format!("cat: {}: No such file or directory\r\n", file_path));
                }
            }
        }

        // Successful content goes to stdout; error diagnostics go to stderr (Err).
        // When both are present we prefer stdout so pipe consumers get real content.
        if output.is_empty() && !errors.is_empty() {
            Err(super::command_trait::CommandError::ExecutionError(errors))
        } else {
            Ok(output)
        }
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
}