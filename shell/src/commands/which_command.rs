use super::command_trait::{Command, CommandError, CommandResult};
use super::context::CommandContext;
use crate::filesystem::fs2::{FileContent, FileSystem};
use async_trait::async_trait;

/// WHICH command - locate commands in the virtual filesystem's PATH,
/// mirroring Debian's `which` (debianutils).
pub struct WhichCommand;

/// Canonical locations for commands the honeypot shell implements but that are
/// absent from the Debian bootstrap filesystem (`base.tar.gz`). Consulted when
/// the PATH scan finds nothing so that `which` stays consistent with what the
/// shell itself can execute.
const SHELL_COMMAND_PATHS: &[(&str, &str)] = &[
    ("column", "/usr/bin/column"),
    ("curl", "/usr/bin/curl"),
    ("strings", "/usr/bin/strings"),
    ("sudo", "/usr/bin/sudo"),
    ("wget", "/usr/bin/wget"),
];

/// Default PATH used when the session environment does not define one
/// (mirrors `CommandContext::new`).
const DEFAULT_PATH: &str = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin";

#[async_trait]
impl Command for WhichCommand {
    fn name(&self) -> &'static str {
        "which"
    }

    fn help(&self) -> String {
        "Usage: which [options] [--] programname [...]\n\
        Options:\n\
        -a, --all           Print all matching executables in PATH, not just the first\n\
        -s, --silent, -q    No output, just return the exit status\n\
        --help              display this help and exit\n\
        --version           output version information and exit\n"
            .to_string()
    }

    fn version(&self) -> String {
        "Debian which, version 2.21, Copyright 2002 by Clinton H. Adams.\n".to_string()
    }

    async fn execute(&self, args: &[String], context: &mut CommandContext) -> CommandResult {
        if args.iter().any(|a| a == "--help") {
            return Ok(self.help());
        }

        if args.iter().any(|a| a == "--version") {
            return Ok(self.version());
        }

        let all = args.iter().any(|a| a == "-a" || a == "--all");
        // Positional arguments are the names to look up; unknown options are
        // ignored (including `-q`/`-s`, whose behaviour equals the default).
        let names: Vec<&String> = args.iter().filter(|a| !a.starts_with('-')).collect();
        if names.is_empty() {
            return Err(CommandError::SilentFailure);
        }

        let path_dirs: Vec<String> = context
            .get_env("PATH")
            .cloned()
            .unwrap_or_else(|| DEFAULT_PATH.to_string())
            .split(':')
            .filter(|d| !d.is_empty())
            .map(|d| d.trim_end_matches('/').to_string())
            .collect();

        let fs = context.filesystem.read().await;

        let mut output = String::new();
        for name in names {
            if name.contains('/') {
                // Path-qualified lookup: print the argument as-is when it
                // points at an existing file (relative paths resolve against cwd).
                let abs = if name.starts_with('/') {
                    name.clone()
                } else {
                    format!("{}/{}", context.cwd.trim_end_matches('/'), name)
                };
                if is_regular_file(&fs, &abs) {
                    output.push_str(name);
                    output.push_str("\r\n");
                }
                continue;
            }

            let mut found: Vec<String> = Vec::new();
            for dir in &path_dirs {
                let candidate = format!("{}/{}", dir, name);
                if is_regular_file(&fs, &candidate) {
                    found.push(candidate);
                    if !all {
                        break;
                    }
                }
            }
            if found.is_empty()
                && let Some((_, canonical)) = SHELL_COMMAND_PATHS.iter().find(|(c, _)| c == name)
            {
                found.push(canonical.to_string());
            }
            for m in found {
                output.push_str(&m);
                output.push_str("\r\n");
            }
        }

        if output.is_empty() {
            // Real `which` exits non-zero and prints nothing for names it
            // cannot find; SilentFailure keeps `&&`/`||` chains working.
            return Err(CommandError::SilentFailure);
        }

        Ok(output)
    }
}

/// Whether `path` resolves (through symlinks) to a regular file.
fn is_regular_file(fs: &FileSystem, path: &str) -> bool {
    match fs.follow_symlink(path) {
        Ok(entry) => matches!(
            entry.file_content.as_ref(),
            Some(FileContent::RegularFile(_))
        ),
        Err(_) => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use tokio::sync::RwLock;

    /// Build a context whose filesystem mimics the Debian bootstrap: binaries
    /// under /usr/bin, /bin as a symlink to usr/bin, plus a home directory.
    fn make_context() -> CommandContext {
        let mut fs = FileSystem::default();
        fs.create_directory("/usr").unwrap();
        fs.create_directory("/usr/bin").unwrap();
        fs.create_file("/usr/bin/cat").unwrap();
        fs.create_file("/usr/bin/ls").unwrap();
        fs.create_directory("/home").unwrap();
        fs.create_directory("/home/root").unwrap();
        CommandContext::new(
            "/home/root".to_string(),
            "root".to_string(),
            "host".to_string(),
            Arc::new(RwLock::new(fs)),
            "1".to_string(),
        )
    }

    async fn run(args: &[&str], context: &mut CommandContext) -> CommandResult {
        WhichCommand
            .execute(
                &args.iter().map(|s| s.to_string()).collect::<Vec<_>>(),
                context,
            )
            .await
    }

    #[tokio::test]
    async fn finds_binary_in_path() {
        let mut ctx = make_context();
        let out = run(&["cat"], &mut ctx).await.unwrap();
        assert_eq!(out, "/usr/bin/cat\r\n");
    }

    #[tokio::test]
    async fn multiple_names_print_only_found() {
        let mut ctx = make_context();
        // `ls` exists in the fake FS, `python3` does not. Real which prints the
        // match and still exits non-zero; the trait cannot express stdout with
        // failure, so a partial match succeeds.
        let out = run(&["python3", "ls"], &mut ctx).await.unwrap();
        assert_eq!(out, "/usr/bin/ls\r\n");
    }

    #[tokio::test]
    async fn not_found_is_silent_failure() {
        let mut ctx = make_context();
        let err = run(&["python3"], &mut ctx).await.unwrap_err();
        assert!(matches!(err, CommandError::SilentFailure));
    }

    #[tokio::test]
    async fn no_names_is_silent_failure() {
        let mut ctx = make_context();
        let err = run(&[], &mut ctx).await.unwrap_err();
        assert!(matches!(err, CommandError::SilentFailure));
    }

    #[tokio::test]
    async fn all_flag_prints_every_path_match() {
        let mut ctx = make_context();
        // Add a second match later in PATH (/usr/bin comes before /bin).
        {
            let mut fs = ctx.filesystem.write().await;
            fs.create_directory("/bin").unwrap();
            fs.create_file("/bin/ls").unwrap();
        }
        let out = run(&["-a", "ls"], &mut ctx).await.unwrap();
        assert_eq!(out, "/usr/bin/ls\r\n/bin/ls\r\n");
    }

    #[tokio::test]
    async fn path_qualified_name_printed_as_given() {
        let mut ctx = make_context();
        let out = run(&["/usr/bin/cat"], &mut ctx).await.unwrap();
        assert_eq!(out, "/usr/bin/cat\r\n");

        // Relative paths resolve against the cwd: present -> printed as given,
        // absent -> not found.
        {
            let mut fs = ctx.filesystem.write().await;
            fs.create_file("/home/root/cat").unwrap();
        }
        let out = run(&["./cat"], &mut ctx).await.unwrap();
        assert_eq!(out, "./cat\r\n");

        let err = run(&["./missing"], &mut ctx).await.unwrap_err();
        assert!(matches!(err, CommandError::SilentFailure));
    }

    #[tokio::test]
    async fn shell_command_fallback() {
        let mut ctx = make_context();
        // wget/curl/sudo are implemented by the shell but absent from the
        // bootstrap filesystem; `which` must still report them.
        for name in ["wget", "curl", "sudo", "strings", "column"] {
            let out = run(&[name], &mut ctx).await.unwrap();
            assert_eq!(
                out,
                format!("/usr/bin/{}\r\n", name),
                "unexpected result for {}",
                name
            );
        }
    }

    #[tokio::test]
    async fn path_env_change_is_respected() {
        let mut ctx = make_context();
        ctx.set_env("PATH".to_string(), "/usr/bin".to_string());
        let out = run(&["cat"], &mut ctx).await.unwrap();
        assert_eq!(out, "/usr/bin/cat\r\n");

        ctx.set_env("PATH".to_string(), "/nonexistent".to_string());
        let err = run(&["cat"], &mut ctx).await.unwrap_err();
        assert!(matches!(err, CommandError::SilentFailure));
    }

    #[tokio::test]
    async fn help_and_version() {
        let mut ctx = make_context();
        let out = run(&["--help"], &mut ctx).await.unwrap();
        assert!(out.contains("Usage: which"));

        let out = run(&["--version"], &mut ctx).await.unwrap();
        assert!(out.contains("Debian which"));
    }
}
