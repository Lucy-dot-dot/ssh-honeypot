use async_trait::async_trait;
use super::command_trait::{Command, StatefulCommand, CommandResult};
use super::context::CommandContext;
use crate::shell::filesystem::fs2::FileContent;

/// PWD command - print working directory
pub struct PwdCommand;

#[async_trait]
impl Command for PwdCommand {
    fn name(&self) -> &'static str {
        "pwd"
    }
    
    async fn execute(&self, _args: &str, context: &mut CommandContext) -> CommandResult {
        Ok(format!("{}\r\n", context.cwd))
    }
}

/// WHOAMI command - print current username
pub struct WhoamiCommand;

#[async_trait]
impl Command for WhoamiCommand {
    fn name(&self) -> &'static str {
        "whoami"
    }
    
    async fn execute(&self, _args: &str, context: &mut CommandContext) -> CommandResult {
        Ok(format!("{}\r\n", context.username))
    }
}

/// ID command - print user and group IDs
pub struct IdCommand;

#[async_trait]
impl Command for IdCommand {
    fn name(&self) -> &'static str {
        "id"
    }
    
    fn help(&self) -> String {
        "Usage: id [OPTION]... [USER]\n\
        Print user and group information for the specified USER,\n\
        or (when USER omitted) for the current user.\n\
        \n\
        -g, --group    print only the effective group ID\n\
        -G, --groups   print all group IDs\n\
        -n, --name     print a name instead of a number, for -ugG\n\
        -r, --real     print the real ID instead of the effective ID, with -ugG\n\
        -u, --user     print only the effective user ID\n\
        --help         display this help and exit\n\
        --version      output version information and exit\n".to_string()
    }
    
    async fn execute(&self, args: &str, context: &mut CommandContext) -> CommandResult {
        if args.contains("--help") {
            return Ok(self.help());
        }
        
        if args.contains("--version") {
            return Ok("id (GNU coreutils) 8.32\n".to_string());
        }
        
        // Simple implementation - just return fake but realistic ID info
        let username = &context.username;
        Ok(format!(
            "uid=1000({}) gid=1000({}) groups=1000({}),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),120(lpadmin),131(lxd),132(sambashare)\r\n",
            username, username, username
        ))
    }
}

/// CD command - change directory (stateful)
pub struct CdCommand;

#[async_trait]
impl Command for CdCommand {
    fn name(&self) -> &'static str {
        "cd"
    }
    
    fn help(&self) -> String {
        "Usage: cd [DIRECTORY]\n\
        Change the current directory to DIRECTORY.\n\
        If no DIRECTORY is given, change to the home directory.\n".to_string()
    }
    
    async fn execute(&self, args: &str, context: &mut CommandContext) -> CommandResult {
        // This shouldn't be called for stateful commands - redirect to stateful version
        self.execute_with_state_change(args, context).await
    }
}

#[async_trait]
impl StatefulCommand for CdCommand {
    
    async fn execute_with_state_change(&self, args: &str, context: &mut CommandContext) -> CommandResult {
        let args = args.trim();
        
        if args == "--help" {
            return Ok(self.help());
        }
        
        // Determine target directory
        let target_dir = if args.is_empty() || args == "~" {
            // Go to home directory
            format!("/home/{}", context.username)
        } else if args == "-" {
            // Go to previous directory (simplified: just go to home)
            format!("/home/{}", context.username)
        } else if args.starts_with('/') {
            // Absolute path
            args.to_string()
        } else {
            // Relative path
            if context.cwd.ends_with('/') {
                format!("{}{}", context.cwd, args)
            } else {
                format!("{}/{}", context.cwd, args)
            }
        };
        
        // Get filesystem and check if directory exists
        let fs = context.filesystem.read().await;
        let resolved = fs.resolve_absolute_path(&target_dir);
        
        match fs.follow_symlink(&resolved) {
            Ok(entry) => {
                match &entry.file_content {
                    Some(FileContent::Directory(_)) => {
                        drop(fs); // Release the filesystem lock before modifying context
                        // Update the current working directory
                        context.set_cwd(resolved);
                        Ok(String::new()) // cd doesn't output anything on success
                    },
                    Some(FileContent::RegularFile(_)) => {
                        Ok(format!("bash: cd: {}: Not a directory\r\n", resolved))
                    },
                    Some(FileContent::SymbolicLink(_)) => {
                        Ok(format!("bash: cd: {}: Not a directory\r\n", resolved))
                    },
                    None => {
                        Ok(format!("bash: cd: {}: No such file or directory\r\n", resolved))
                    }
                }
            },
            Err(_) => {
                Ok(format!("bash: cd: {}: No such file or directory\r\n", resolved))
            }
        }
    }
}

/// WGET command - web downloader (fake)
pub struct WgetCommand;

#[async_trait]
impl Command for WgetCommand {
    fn name(&self) -> &'static str {
        "wget"
    }
    
    fn help(&self) -> String {
        "Usage: wget [OPTION]... [URL]...\n\
        --help     display this help and exit\n\
        --version  output version information and exit\n".to_string()
    }
    
    async fn execute(&self, args: &str, _context: &mut CommandContext) -> CommandResult {
        if args.contains("--help") {
            return Ok(self.help());
        }
        
        if args.contains("--version") {
            return Ok("GNU Wget 1.20.3\n".to_string());
        }
        
        Ok("wget: missing URL\r\nUsage: wget [OPTION]... [URL]...\r\n\r\nTry `wget --help' for more options.\r\n".to_string())
    }
}

/// CURL command - URL transfer tool (fake)
pub struct CurlCommand;

#[async_trait]
impl Command for CurlCommand {
    fn name(&self) -> &'static str {
        "curl"
    }
    
    fn help(&self) -> String {
        "Usage: curl [options...] <url>\n\
        --help     Show help for all options\n\
        --version  Show version\n".to_string()
    }
    
    async fn execute(&self, args: &str, _context: &mut CommandContext) -> CommandResult {
        if args.contains("--help") {
            return Ok(self.help());
        }
        
        if args.contains("--version") {
            return Ok("curl 7.68.0\n".to_string());
        }
        
        Ok("curl: try 'curl --help' or 'curl --manual' for more information\r\n".to_string())
    }
}

/// SUDO command - always deny with realistic message
pub struct SudoCommand;

#[async_trait]
impl Command for SudoCommand {
    fn name(&self) -> &'static str {
        "sudo"
    }
    
    async fn execute(&self, _args: &str, context: &mut CommandContext) -> CommandResult {
        Ok(format!("Sorry, user {} may not run sudo on {}.\r\n", context.username, context.hostname))
    }
}

/// EXIT command - placeholder (actual exit is handled in server)
pub struct ExitCommand;

#[async_trait]
impl Command for ExitCommand {
    fn name(&self) -> &'static str {
        "exit"
    }
    
    fn aliases(&self) -> Vec<&'static str> {
        vec!["logout"]
    }
    
    async fn execute(&self, _args: &str, _context: &mut CommandContext) -> CommandResult {
        // This will be handled specially by the server
        Ok(String::new())
    }
}