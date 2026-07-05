use super::command_trait::{Command, CommandError, CommandResult, StatefulCommand};
use super::context::CommandContext;
use crate::shell::filesystem::fs2::FileContent;
use async_trait::async_trait;

/// PWD command - print working directory
pub struct PwdCommand;

#[async_trait]
impl Command for PwdCommand {
    fn name(&self) -> &'static str {
        "pwd"
    }

    async fn execute(&self, _args: &[String], context: &mut CommandContext) -> CommandResult {
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

    async fn execute(&self, _args: &[String], context: &mut CommandContext) -> CommandResult {
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
        --version      output version information and exit\n"
            .to_string()
    }

    async fn execute(&self, args: &[String], context: &mut CommandContext) -> CommandResult {
        if args.iter().any(|a| a == "--help") {
            return Ok(self.help());
        }

        if args.iter().any(|a| a == "--version") {
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
        If no DIRECTORY is given, change to the home directory.\n"
            .to_string()
    }

    async fn execute(&self, args: &[String], context: &mut CommandContext) -> CommandResult {
        // This shouldn't be called for stateful commands - redirect to stateful version
        self.execute_with_state_change(args, context).await
    }
}

#[async_trait]
impl StatefulCommand for CdCommand {
    async fn execute_with_state_change(
        &self,
        args: &[String],
        context: &mut CommandContext,
    ) -> CommandResult {
        if args.iter().any(|a| a == "--help") {
            return Ok(self.help());
        }

        // Determine target directory
        let raw = args
            .iter()
            .find(|a| !a.starts_with('-'))
            .map(|s| s.as_str())
            .unwrap_or("");
        let target_dir = if raw.is_empty() || raw == "~" {
            // Go to home directory
            format!("/home/{}", context.username)
        } else if raw == "-" {
            // Go to previous directory (simplified: just go to home)
            format!("/home/{}", context.username)
        } else if let Some(expanded) = raw.strip_prefix("~/") {
            format!("/home/{}/{}", context.username, expanded)
        } else if raw.starts_with('/') {
            // Absolute path
            raw.to_string()
        } else {
            // Relative path
            if context.cwd.ends_with('/') {
                format!("{}{}", context.cwd, raw)
            } else {
                format!("{}/{}", context.cwd, raw)
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
                    }
                    Some(FileContent::RegularFile(_)) => {
                        Ok(format!("bash: cd: {}: Not a directory\r\n", resolved))
                    }
                    Some(FileContent::SymbolicLink(_)) => {
                        Ok(format!("bash: cd: {}: Not a directory\r\n", resolved))
                    }
                    None => Ok(format!(
                        "bash: cd: {}: No such file or directory\r\n",
                        resolved
                    )),
                }
            }
            Err(_) => Ok(format!(
                "bash: cd: {}: No such file or directory\r\n",
                resolved
            )),
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
        --version  output version information and exit\n"
            .to_string()
    }

    async fn execute(&self, args: &[String], _context: &mut CommandContext) -> CommandResult {
        if args.iter().any(|a| a == "--help") {
            return Ok(self.help());
        }

        if args.iter().any(|a| a == "--version") {
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
        --version  Show version\n"
            .to_string()
    }

    async fn execute(&self, args: &[String], _context: &mut CommandContext) -> CommandResult {
        if args.iter().any(|a| a == "--help") {
            return Ok(self.help());
        }

        if args.iter().any(|a| a == "--version") {
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

    async fn execute(&self, _args: &[String], context: &mut CommandContext) -> CommandResult {
        Ok(format!(
            "Sorry, user {} may not run sudo on {}.\r\n",
            context.username, context.hostname
        ))
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

    async fn execute(&self, _args: &[String], _context: &mut CommandContext) -> CommandResult {
        // This will be handled specially by the server
        Ok(String::new())
    }
}

/// TRUE command - always succeeds (exit status 0).
pub struct TrueCommand;

#[async_trait]
impl Command for TrueCommand {
    fn name(&self) -> &'static str {
        "true"
    }

    async fn execute(&self, _args: &[String], _context: &mut CommandContext) -> CommandResult {
        Ok(String::new())
    }
}

/// FALSE command - always fails (exit status 1).
pub struct FalseCommand;

#[async_trait]
impl Command for FalseCommand {
    fn name(&self) -> &'static str {
        "false"
    }

    async fn execute(&self, _args: &[String], _context: &mut CommandContext) -> CommandResult {
        Err(CommandError::SilentFailure)
    }
}

/// COLON (`:`) command - null command that always succeeds.
pub struct ColonCommand;

#[async_trait]
impl Command for ColonCommand {
    fn name(&self) -> &'static str {
        ":"
    }

    async fn execute(&self, _args: &[String], _context: &mut CommandContext) -> CommandResult {
        Ok(String::new())
    }
}

/// EXPORT command - set environment variables.
pub struct ExportCommand;

#[async_trait]
impl Command for ExportCommand {
    fn name(&self) -> &'static str {
        "export"
    }

    async fn execute(&self, args: &[String], context: &mut CommandContext) -> CommandResult {
        for arg in args {
            if let Some(eq) = arg.find('=') {
                let name = arg[..eq].to_string();
                let value = arg[eq + 1..].to_string();
                if !name.is_empty() && name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
                {
                    context.set_env(name, value);
                }
            }
            // `export VAR` (no `=`) is a no-op here (variable already exported
            // implicitly by being in the environment).
        }
        Ok(String::new())
    }
}

/// UNSET command - remove environment variables.
pub struct UnsetCommand;

#[async_trait]
impl Command for UnsetCommand {
    fn name(&self) -> &'static str {
        "unset"
    }

    async fn execute(&self, args: &[String], context: &mut CommandContext) -> CommandResult {
        for arg in args {
            if !arg.starts_with('-') {
                context.env_vars.remove(arg);
            }
        }
        Ok(String::new())
    }
}
