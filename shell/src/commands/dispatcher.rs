use super::command_trait::CommandError;
use super::context::CommandContext;
use super::registry::CommandRegistry;
use crate::filters;
use crate::parser::{self, AndOp, CommandList, Redirect};
use std::future::Future;
use std::pin::Pin;

/// Outcome of executing a full command line.
pub struct ExecutionOutcome {
    /// Text to display to the client.
    pub output: String,
    /// Whether the user requested the session to end (`exit` / `logout`).
    pub exit_requested: bool,
    /// Exit status of the last command that ran (bash semantics: 0 success,
    /// 1 generic failure, 126 permission denied, 127 command not found).
    pub exit_code: i32,
}

/// Handles command parsing and execution.
pub struct CommandDispatcher {
    registry: CommandRegistry,
}

/// Internal result of running a single pipeline.
struct PipeResult {
    stdout: String,
    stderr: String,
    /// Exit status of the pipeline's last executed command.
    exit_code: i32,
    exit_requested: bool,
}

/// Map a command error to a bash-style exit status.
fn error_exit_code(e: &CommandError) -> i32 {
    match e {
        CommandError::SilentFailure => 1,
        CommandError::NotFound(_) => 127,
        CommandError::PermissionDenied(_) => 126,
        CommandError::InvalidArguments(_)
        | CommandError::FilesystemError(_)
        | CommandError::ExecutionError(_) => 1,
    }
}

/// Replace the parser's `$?` sentinel with the live exit status.
fn expand_exit_status(s: &str, code: i32) -> String {
    if s.contains(parser::EXIT_STATUS_SENTINEL) {
        s.replace(parser::EXIT_STATUS_SENTINEL, &code.to_string())
    } else {
        s.to_string()
    }
}

#[allow(dead_code)]
impl CommandDispatcher {
    /// Create a new command dispatcher with an empty registry
    pub fn new() -> Self {
        Self {
            registry: CommandRegistry::new(),
        }
    }

    /// Create a new command dispatcher with the given registry
    pub fn with_registry(registry: CommandRegistry) -> Self {
        Self { registry }
    }

    /// Get a mutable reference to the registry for command registration
    pub fn registry_mut(&mut self) -> &mut CommandRegistry {
        &mut self.registry
    }

    /// Execute a full command line (handles parsing, pipes, sequencing, &&/||,
    /// command substitution, arithmetic, assignments and redirections).
    pub async fn execute(
        &self,
        command_line: &str,
        context: &mut CommandContext,
    ) -> ExecutionOutcome {
        if command_line.trim().is_empty() {
            return ExecutionOutcome {
                output: String::new(),
                exit_requested: false,
                exit_code: 0,
            };
        }

        let resolved = self.resolve_substitutions(command_line, context).await;
        if resolved.trim().is_empty() {
            return ExecutionOutcome {
                output: String::new(),
                exit_requested: false,
                exit_code: 0,
            };
        }

        let home = context
            .get_env("HOME")
            .cloned()
            .unwrap_or_else(|| format!("/home/{}", context.username));
        let script = parser::parse_script(&resolved, &context.env_vars, &home);

        let (stdout, stderr, exit, code) = self.run_nodes(&script.nodes, context).await;
        let mut output = stdout;
        output.push_str(&stderr);
        // Publish the final status so later lines (and command substitutions)
        // observe it through `$?`.
        context
            .env_vars
            .insert(parser::EXIT_STATUS_VAR.to_string(), code.to_string());

        ExecutionOutcome {
            output,
            exit_requested: exit,
            exit_code: code,
        }
    }

    /// Resolve `$(...)` command substitution and `$((...))` arithmetic (including
    /// assignment forms `IDENT=$(...)` / `IDENT=$((...))`) in a raw line.
    async fn resolve_substitutions(&self, s: &str, context: &mut CommandContext) -> String {
        let mut current = s.to_string();
        for _ in 0..200 {
            let chars: Vec<char> = current.chars().collect();
            let n = chars.len();

            // Find the first "$((" or "$("
            let mut dollar_idx: Option<usize> = None;
            let mut is_arith = false;
            for i in 0..n.saturating_sub(1) {
                if chars[i] == '$' && chars[i + 1] == '(' {
                    is_arith = i + 2 < n && chars[i + 2] == '(';
                    dollar_idx = Some(i);
                    break;
                }
            }
            let Some(di) = dollar_idx else { break };

            let (body, end_idx) = if is_arith {
                find_arith_end(&chars, di + 3)
            } else {
                find_cmdsubst_end(&chars, di + 2)
            };

            // Detect an assignment prefix `IDENT=` immediately before the substitution.
            let mut k = di;
            while k > 0 {
                let ch = chars[k - 1];
                if ch.is_ascii_alphanumeric() || ch == '_' || ch == '=' {
                    k -= 1;
                } else {
                    break;
                }
            }
            let word_before: String = chars[k..di].iter().collect();
            let is_assign = parser::parse_assignment(&word_before).is_some();

            let value: String = if is_arith {
                if parser::looks_like_command(&body) {
                    self.run_line_capture(&body, context).await
                } else {
                    parser::eval_arithmetic(&body, &context.env_vars).to_string()
                }
            } else {
                self.run_line_capture(&body, context).await
            };

            if is_assign {
                if let Some((name, _)) = parser::parse_assignment(&word_before) {
                    context.env_vars.insert(name, value.trim().to_string());
                }
                let before: String = chars[..k].iter().collect();
                let after: String = chars[end_idx..].iter().collect();
                current = format!("{}{}", before, after);
            } else {
                let before: String = chars[..di].iter().collect();
                let after: String = chars[end_idx..].iter().collect();
                current = format!("{}{}{}", before, value, after);
            }
        }
        current
    }

    /// Run a line and return only its captured stdout (trimmed) - used by command
    /// substitution. Any stderr produced by inner commands is discarded.
    fn run_line_capture<'a>(
        &'a self,
        line: &'a str,
        context: &'a mut CommandContext,
    ) -> Pin<Box<dyn Future<Output = String> + Send + 'a>> {
        Box::pin(async move {
            let resolved = self.resolve_substitutions(line, context).await;
            if resolved.trim().is_empty() {
                return String::new();
            }
            let home = context
                .get_env("HOME")
                .cloned()
                .unwrap_or_else(|| format!("/home/{}", context.username));
            let script = parser::parse_script(&resolved, &context.env_vars, &home);
            let (stdout, _stderr, _exit, _) = self.run_nodes(&script.nodes, context).await;
            stdout.trim().to_string()
        })
    }

    /// Run a full command list honouring `&&` / `||` / `;` sequencing.
    /// Returns `(stdout, stderr, exit_requested, last_exit_code)`.
    async fn run_command_list(
        &self,
        list: &CommandList,
        context: &mut CommandContext,
    ) -> (String, String, bool, i32) {
        let mut stdout = String::new();
        let mut stderr = String::new();
        let mut exit = false;
        let mut last_exit = 0;
        let mut should_run = true;

        for item in &list.items {
            if should_run {
                let r = self.run_pipeline(&item.pipeline, context).await;
                stdout.push_str(&r.stdout);
                stderr.push_str(&r.stderr);
                exit |= r.exit_requested;
                last_exit = r.exit_code;
                // Publish after every pipeline so `false || echo $?` and
                // friends observe the intermediate status.
                context
                    .env_vars
                    .insert(parser::EXIT_STATUS_VAR.to_string(), last_exit.to_string());
                if exit {
                    // `exit`/`logout` fired: stop the whole list like bash.
                    break;
                }
            }
            should_run = match item.op {
                AndOp::Then => true,
                AndOp::And => last_exit == 0,
                AndOp::Or => last_exit != 0,
            };
        }

        (stdout, stderr, exit, last_exit)
    }

    /// Run a sequence of parsed nodes (control flow + command lists).
    /// Returns `(stdout, stderr, exit_requested, last_exit_code)`.
    /// Boxed to break the async recursion cycle with `run_node` (nested control
    /// flow like `if` inside `if`).
    fn run_nodes<'a>(
        &'a self,
        nodes: &'a [parser::Node],
        context: &'a mut CommandContext,
    ) -> Pin<Box<dyn Future<Output = (String, String, bool, i32)> + Send + 'a>> {
        Box::pin(async move {
            let mut stdout = String::new();
            let mut stderr = String::new();
            let mut exit = false;
            let mut last_exit = 0;
            for node in nodes {
                let (o, e, ex, code) = self.run_node(node, context).await;
                stdout.push_str(&o);
                stderr.push_str(&e);
                exit |= ex;
                last_exit = code;
                if exit {
                    break;
                }
            }
            (stdout, stderr, exit, last_exit)
        })
    }

    /// Execute a single parsed node. Returns `(stdout, stderr, exit, exit_code)`.
    async fn run_node(
        &self,
        node: &parser::Node,
        context: &mut CommandContext,
    ) -> (String, String, bool, i32) {
        match node {
            parser::Node::Seq(list) => self.run_command_list(list, context).await,
            parser::Node::If {
                branches,
                else_body,
            } => {
                let mut stdout = String::new();
                let mut stderr = String::new();
                for (cond, body) in branches {
                    let (o, e, _ex, code) = self.run_nodes(cond, context).await;
                    stdout.push_str(&o);
                    stderr.push_str(&e);
                    if code == 0 {
                        let (o2, e2, ex2, c2) = self.run_nodes(body, context).await;
                        stdout.push_str(&o2);
                        stderr.push_str(&e2);
                        return (stdout, stderr, ex2, c2);
                    }
                }
                if let Some(els) = else_body {
                    let (o, e, ex, code) = self.run_nodes(els, context).await;
                    stdout.push_str(&o);
                    stderr.push_str(&e);
                    return (stdout, stderr, ex, code);
                }
                (stdout, stderr, false, 0)
            }
            parser::Node::For { var, words, body } => {
                let mut stdout = String::new();
                let mut stderr = String::new();
                let mut exit = false;
                let mut last_exit = 0;
                let saved = context.env_vars.get(var).cloned();
                for w in words {
                    context.env_vars.insert(var.clone(), w.clone());
                    let (o, e, ex, code) = self.run_nodes(body, context).await;
                    stdout.push_str(&o);
                    stderr.push_str(&e);
                    exit |= ex;
                    last_exit = code;
                    if exit {
                        break;
                    }
                }
                match saved {
                    Some(v) => {
                        context.env_vars.insert(var.clone(), v);
                    }
                    None => {
                        context.env_vars.remove(var);
                    }
                }
                (stdout, stderr, exit, last_exit)
            }
            parser::Node::While { cond, body, until } => {
                let mut stdout = String::new();
                let mut stderr = String::new();
                let mut exit = false;
                for _ in 0..10000 {
                    let (_o, _e, _ex, code) = self.run_nodes(cond, context).await;
                    let keep_going = if *until { code != 0 } else { code == 0 };
                    if !keep_going {
                        break;
                    }
                    let (o, e, ex, _) = self.run_nodes(body, context).await;
                    stdout.push_str(&o);
                    stderr.push_str(&e);
                    exit |= ex;
                    if exit {
                        break;
                    }
                }
                (stdout, stderr, exit, 0)
            }
        }
    }

    /// Run a single pipeline, threading each stage's stdout into the next stage's
    /// stdin. Per-command redirections are applied (stdout/stderr separation).
    async fn run_pipeline(
        &self,
        pipeline: &parser::Pipeline,
        context: &mut CommandContext,
    ) -> PipeResult {
        let mut stdout = String::new();
        let mut stderr_acc = String::new();
        let mut exit_code = 0;
        let mut exit_requested = false;

        // Status of the previous pipeline: `$?` inside this pipeline (any
        // stage) expands to it, matching bash which expands a pipeline's
        // words before it starts running.
        let prev_exit: i32 = context
            .env_vars
            .get(parser::EXIT_STATUS_VAR)
            .and_then(|v| v.parse().ok())
            .unwrap_or(0);

        for (idx, cmd) in pipeline.commands.iter().enumerate() {
            if cmd.name.is_empty() {
                continue;
            }

            // Defer `$?` expansion until execution time: substitute the
            // previous pipeline's status now, before anything runs.
            let name = expand_exit_status(&cmd.name, prev_exit);
            let args: Vec<String> = cmd
                .args
                .iter()
                .map(|a| expand_exit_status(a, prev_exit))
                .collect();

            if name == "exit" || name == "logout" {
                exit_requested = true;
                exit_code = match args.first() {
                    None => prev_exit,
                    Some(arg) => match arg.trim().parse::<i32>() {
                        Ok(n) => n & 0xFF,
                        Err(_) => {
                            stderr_acc.push_str(&format!(
                                "bash: exit: {}: numeric argument required\r\n",
                                arg
                            ));
                            2
                        }
                    },
                };
                break;
            }

            let is_first = idx == 0;
            let stdin = if is_first {
                String::new()
            } else {
                stdout.clone()
            };

            // Bare variable assignment `VAR=value` (RHS already expanded).
            if let Some((var, val)) = parser::parse_assignment(&name) {
                context.env_vars.insert(var, val);
                if args.is_empty() {
                    exit_code = 0;
                    continue;
                }
                // `VAR=value command args`: set env var then run the real command.
                let real_name = args[0].clone();
                let real_args: Vec<String> = args[1..].to_vec();
                let (mut out, mut err, code) = self
                    .dispatch_one(&real_name, &real_args, &stdin, is_first, context)
                    .await;
                Self::apply_redirects(&mut out, &mut err, &cmd.redirects);
                stdout = out;
                stderr_acc.push_str(&err);
                exit_code = code;
                continue;
            }

            let (mut out, mut err, code) = self
                .dispatch_one(&name, &args, &stdin, is_first, context)
                .await;
            Self::apply_redirects(&mut out, &mut err, &cmd.redirects);
            stdout = out;
            stderr_acc.push_str(&err);
            exit_code = code;
        }

        PipeResult {
            stdout,
            stderr: stderr_acc,
            exit_code,
            exit_requested,
        }
    }

    /// Dispatch a single command/filter, returning `(stdout, stderr, exit_code)`.
    async fn dispatch_one(
        &self,
        name: &str,
        args: &[String],
        stdin: &str,
        is_first: bool,
        context: &mut CommandContext,
    ) -> (String, String, i32) {
        if name.is_empty() {
            return (String::new(), String::new(), 0);
        }

        // Commands invoked through a path ("/usr/bin/cat", "./echo", "../bin/ls")
        // resolve to their basename so they hit the same implementation as the
        // bare name. Filters and registry lookups both use the resolved name.
        let path_base = resolve_command_path(name);
        let lookup = path_base.unwrap_or(name);
        let not_found = if path_base.is_some() {
            // bash reports a different error for path-qualified commands.
            format!("bash: {}: No such file or directory\r\n", name)
        } else {
            format!("bash: {}: command not found\r\n", name)
        };

        if filters::is_filter(lookup) && (!is_first || !self.registry.has_command(lookup)) {
            match filters::apply_filter(lookup, args, stdin, context).await {
                Some((out, succ)) => (out, String::new(), i32::from(!succ)),
                None => (String::new(), not_found, 127),
            }
        } else if self.registry.has_command(lookup) {
            match self.registry.execute_command(lookup, args, context).await {
                Ok(out) => (out, String::new(), 0),
                Err(e) => {
                    let msg = format!("{}\r\n", e);
                    (String::new(), msg, error_exit_code(&e))
                }
            }
        } else {
            (String::new(), not_found, 127)
        }
    }

    /// Apply redirections to a command's stdout/stderr. File-target redirections
    /// discard the stream (best-effort for the honeypot); `/dev/null` discards;
    /// `N>&M` merges streams.
    fn apply_redirects(stdout: &mut String, stderr: &mut String, redirects: &[Redirect]) {
        for r in redirects {
            let devnull = matches!(&r.target, parser::RedirTarget::DevNull);
            match r.fd {
                1 if devnull => stdout.clear(),
                2 if devnull => stderr.clear(),
                1 if matches!(&r.target, parser::RedirTarget::Fd(2)) => {
                    let s = std::mem::take(stdout);
                    stderr.push_str(&s);
                }
                2 if matches!(&r.target, parser::RedirTarget::Fd(1)) => {
                    let s = std::mem::take(stderr);
                    stdout.push_str(&s);
                }
                1 if matches!(&r.target, parser::RedirTarget::File(_)) => stdout.clear(),
                2 if matches!(&r.target, parser::RedirTarget::File(_)) => stderr.clear(),
                _ => {}
            }
        }
    }

    /// Check if a command exists in the registry
    pub fn has_command(&self, command_name: &str) -> bool {
        self.registry.has_command(command_name)
    }

    /// Get help for a command
    pub async fn get_help(&self, command_name: &str) -> Option<String> {
        self.registry.get_command_help(command_name).await
    }

    /// Get all available commands
    pub fn list_commands(&self) -> Vec<String> {
        self.registry.get_command_names()
    }
}

impl Default for CommandDispatcher {
    fn default() -> Self {
        Self::new()
    }
}

/// Resolve a command invoked through a path to its basename:
/// `/usr/bin/cat` -> `cat`, `./echo` -> `echo`, `../bin/ls` -> `ls`.
/// Returns `None` when the name contains no path component or the path
/// is empty (`/`, `foo/`), in which case the name is used as-is.
fn resolve_command_path(name: &str) -> Option<&str> {
    if !name.contains('/') {
        return None;
    }
    let base = name.trim_end_matches('/').rsplit('/').next()?;
    if base.is_empty() { None } else { Some(base) }
}

/// Find the end of a `$(...)` command substitution. `start` is the index just
/// after `$(`. Returns `(body, end_index)` where `end_index` is the first char
/// after the closing `)`.
fn find_cmdsubst_end(chars: &[char], start: usize) -> (String, usize) {
    let mut depth: i32 = 0;
    let mut i = start;
    let mut in_s = false;
    let mut in_d = false;
    while i < chars.len() {
        let c = chars[i];
        if in_s {
            if c == '\'' {
                in_s = false;
            }
            i += 1;
            continue;
        }
        if in_d {
            if c == '"' {
                in_d = false;
            }
            i += 1;
            continue;
        }
        match c {
            '\'' => in_s = true,
            '"' => in_d = true,
            '(' => depth += 1,
            ')' => {
                if depth == 0 {
                    let body: String = chars[start..i].iter().collect();
                    return (body, i + 1);
                }
                depth -= 1;
            }
            _ => {}
        }
        i += 1;
    }
    let body: String = chars[start..].iter().collect();
    (body, chars.len())
}

/// Find the end of a `$((...))` arithmetic expansion. `start` is the index just
/// after `$((`. Returns `(body, end_index)`.
fn find_arith_end(chars: &[char], start: usize) -> (String, usize) {
    let mut depth: i32 = 0;
    let mut i = start;
    let mut in_s = false;
    let mut in_d = false;
    while i < chars.len() {
        let c = chars[i];
        if in_s {
            if c == '\'' {
                in_s = false;
            }
            i += 1;
            continue;
        }
        if in_d {
            if c == '"' {
                in_d = false;
            }
            i += 1;
            continue;
        }
        match c {
            '\'' => in_s = true,
            '"' => in_d = true,
            '(' => depth += 1,
            ')' => {
                if depth == 0 {
                    if chars.get(i + 1) == Some(&')') {
                        let body: String = chars[start..i].iter().collect();
                        return (body, i + 2);
                    } else {
                        let body: String = chars[start..i].iter().collect();
                        return (body, i + 1);
                    }
                }
                depth -= 1;
            }
            _ => {}
        }
        i += 1;
    }
    let body: String = chars[start..].iter().collect();
    (body, chars.len())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commands::{
        CatCommand, ColonCommand, DateCommand, EchoCommand, ExitCommand, ExportCommand,
        FalseCommand, LsCommand, TestCommand, TrueCommand, UnameCommand, UnsetCommand,
    };
    use crate::filesystem::fs2::FileSystem;
    use std::sync::Arc;
    use tokio::sync::RwLock;

    fn make_dispatcher() -> CommandDispatcher {
        let mut d = CommandDispatcher::new();
        d.registry_mut().register_command(Arc::new(EchoCommand));
        d.registry_mut().register_command(Arc::new(CatCommand));
        d.registry_mut().register_command(Arc::new(DateCommand));
        d.registry_mut().register_command(Arc::new(UnameCommand));
        d.registry_mut().register_command(Arc::new(LsCommand));
        d.registry_mut().register_command(Arc::new(ExitCommand));
        d.registry_mut().register_command(Arc::new(TestCommand));
        d.registry_mut().register_command(Arc::new(TrueCommand));
        d.registry_mut().register_command(Arc::new(FalseCommand));
        d.registry_mut().register_command(Arc::new(ColonCommand));
        d.registry_mut().register_command(Arc::new(ExportCommand));
        d.registry_mut().register_command(Arc::new(UnsetCommand));
        d
    }

    fn make_context() -> CommandContext {
        let fs = Arc::new(RwLock::new(FileSystem::default()));
        CommandContext::new(
            "/".to_string(),
            "root".to_string(),
            "host".to_string(),
            fs,
            "1".to_string(),
        )
    }

    #[tokio::test]
    async fn basic_echo() {
        let d = make_dispatcher();
        let mut ctx = make_context();
        let out = d.execute("echo hello world", &mut ctx).await;
        assert!(out.output.contains("hello world"));
    }

    #[tokio::test]
    async fn full_path_command_resolves_to_bare_name() {
        let d = make_dispatcher();
        let mut ctx = make_context();
        let out = d.execute("/bin/echo hello via-path", &mut ctx).await;
        assert!(
            out.output.contains("hello via-path"),
            "output was: {}",
            out.output
        );
    }

    #[tokio::test]
    async fn usr_bin_cat_resolves_to_cat() {
        let d = make_dispatcher();
        let mut ctx = make_context();
        let out = d.execute("echo piped-input | /usr/bin/cat", &mut ctx).await;
        assert!(
            out.output.contains("piped-input"),
            "output was: {}",
            out.output
        );
    }

    #[tokio::test]
    async fn relative_path_command_resolves() {
        let d = make_dispatcher();
        let mut ctx = make_context();
        let out = d.execute("./echo relative-path", &mut ctx).await;
        assert!(
            out.output.contains("relative-path"),
            "output was: {}",
            out.output
        );

        let out = d.execute("echo x | ../bin/grep x", &mut ctx).await;
        assert!(out.output.contains("x"), "output was: {}", out.output);
    }

    #[tokio::test]
    async fn path_filter_as_pipeline_stage() {
        let d = make_dispatcher();
        let mut ctx = make_context();
        let out = d.execute("echo alpha | /usr/bin/grep beta", &mut ctx).await;
        assert!(
            !out.output.contains("alpha"),
            "filter should have consumed input; output was: {}",
            out.output
        );

        let out = d.execute("echo alpha | /bin/grep alpha", &mut ctx).await;
        assert!(out.output.contains("alpha"), "output was: {}", out.output);
    }

    #[tokio::test]
    async fn full_path_unknown_command_bash_error() {
        let d = make_dispatcher();
        let mut ctx = make_context();
        let out = d.execute("/usr/bin/definitely-not-real", &mut ctx).await;
        assert!(
            out.output
                .contains("bash: /usr/bin/definitely-not-real: No such file or directory"),
            "output was: {}",
            out.output
        );

        // Bare unknown names keep the classic "command not found" message.
        let out = d.execute("definitely-not-real", &mut ctx).await;
        assert!(
            out.output
                .contains("bash: definitely-not-real: command not found"),
            "output was: {}",
            out.output
        );
    }

    #[tokio::test]
    async fn assignment_prefix_with_full_path_command() {
        let d = make_dispatcher();
        let mut ctx = make_context();
        // `VAR=value cmd args` runs the path-qualified command with the env set.
        let out = d.execute("V=hello /usr/bin/echo hi", &mut ctx).await;
        assert!(out.output.contains("hi"), "output was: {}", out.output);
        assert!(
            !out.output.contains("command not found"),
            "output was: {}",
            out.output
        );
    }

    #[tokio::test]
    async fn resolve_command_path_basics() {
        assert_eq!(resolve_command_path("/usr/bin/cat"), Some("cat"));
        assert_eq!(resolve_command_path("/bin/ls"), Some("ls"));
        assert_eq!(resolve_command_path("./echo"), Some("echo"));
        assert_eq!(resolve_command_path("../bin/sh"), Some("sh"));
        assert_eq!(resolve_command_path("foo/"), Some("foo"));
        assert_eq!(resolve_command_path("cat"), None);
        assert_eq!(resolve_command_path("/"), None);
    }

    #[tokio::test]
    async fn command_substitution() {
        let d = make_dispatcher();
        let mut ctx = make_context();
        let out = d.execute("x=$(echo captured); echo GOT:$x", &mut ctx).await;
        assert!(
            out.output.contains("GOT:captured"),
            "output was: {}",
            out.output
        );
    }

    #[tokio::test]
    async fn arithmetic_in_echo() {
        let d = make_dispatcher();
        let mut ctx = make_context();
        let out = d.execute("echo $((2 + 3 * 4))", &mut ctx).await;
        assert!(out.output.contains("14"), "output was: {}", out.output);
    }

    #[tokio::test]
    async fn and_or_short_circuit() {
        let d = make_dispatcher();
        let mut ctx = make_context();
        let out = d
            .execute("false_cmd && echo nope || echo yes", &mut ctx)
            .await;
        assert!(out.output.contains("yes"));
        assert!(!out.output.contains("nope"));
    }

    /// Real-world recon payload (system fingerprinting) executed line-by-line as
    /// the honeypot would receive it over SSH. Exercises command substitution,
    /// arithmetic, assignments, subshells, `[`, redirections and pipelines.
    #[tokio::test]
    async fn real_recon_fingerprint_script() {
        let script = r#"
		uname=$(uname -s -v -n -m 2>/dev/null);
		arch=$(uname -m 2>/dev/null);
		uptime=$(awk '{u=int($1);d=int(u/86400);h=int((u%86400)/3600);m=int((u%3600)/60);s="";if(d>0)s=s d"d";if(h>0){if(s!="")s=s", ";s=s h"h"}if(m>0||s==""){if(s!="")s=s", ";s=s m"m"}print s}' /proc/uptime 2>/dev/null);
		[ -z "$uptime" ] && secondsStr=$(cat /proc/uptime | cut -d' ' -f1 | cut -d. -f1) && [ -n "$secondsStr" ] && seconds=$((secondsStr)) && d=$((seconds/86400)) && h=$(( (seconds%86400)/3600 )) && m=$(( (seconds%3600)/60 )) && uptime="" && [ $d -gt 0 ] && uptime="${uptime}${d}d" && [ $h -gt 0 ] && { [ -n "$uptime" ] && uptime="$uptime, "; uptime="${uptime}${h}h"; } && { [ $m -gt 0 ] || [ -z "$uptime" ]; } && { [ -n "$uptime" ] && uptime="$uptime, "; uptime="${uptime}${m}m"; };
		cpus=$( (nproc || grep -c "^processor" /proc/cpuinfo) 2>/dev/null | head -1);
		cpu_model=$( (grep -m1 "model name" /proc/cpuinfo | cut -d: -f2 | sed 's/^ //;s/ *$//' || lscpu | grep -m1 "Model name" | cut -d: -f2 | sed 's/^ //;s/ *$//') 2>/dev/null);
		gpu_info=$( (lspci | grep -i vga; lspci | grep -i nvidia) 2>/dev/null | head -n50);
		cat_help=$((cat --help 2>&1 | tr '\n' ' ') || cat --help 2>&1);
		ls_help=$((ls --help 2>&1 | tr '\n' ' ') || ls --help 2>&1);
		last_output=$(last 2>/dev/null | head -n 10);
		echo "UNAME:$uname";
		echo "ARCH:$arch";
		echo "UPTIME:$uptime";
		echo "CPUS:$cpus";
		echo "CPU_MODEL:$cpu_model";
		echo "GPU:$gpu_info";
		echo "CAT_HELP:$cat_help";
		echo "LS_HELP:$ls_help";
		echo "LAST:$last_output";
"#;

        let d = make_dispatcher();
        let mut ctx = make_context();

        // Execute line-by-line exactly as the SSH keystroke handler does, sharing
        // one context so environment variables persist across lines.
        let mut output = String::new();
        for line in script.lines() {
            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue;
            }
            let out = d.execute(trimmed, &mut ctx).await;
            output.push_str(&out.output);
        }

        // All nine fingerprint markers must be present.
        for marker in [
            "UNAME:",
            "ARCH:",
            "UPTIME:",
            "CPUS:",
            "CPU_MODEL:",
            "GPU:",
            "CAT_HELP:",
            "LS_HELP:",
            "LAST:",
        ] {
            assert!(
                output.contains(marker),
                "missing marker {:?} in output:\n{}",
                marker,
                output
            );
        }

        // Command substitution must have produced real values from `uname`.
        assert!(
            output.contains("UNAME:Linux"),
            "uname substitution failed; output:\n{}",
            output
        );
        assert!(
            output.contains("ARCH:x86_64"),
            "arch substitution failed; output:\n{}",
            output
        );
        // `cat --help` substitution should yield non-empty help text.
        assert!(
            !output.contains("CAT_HELP:\r\n") && !output.contains("CAT_HELP:\nLAST:"),
            "cat_help should be non-empty; output:\n{}",
            output
        );

        // The uptime block must NOT have leaked cat error text into UPTIME
        // (stdout/stderr separation + `[` short-circuit must keep it clean).
        let uptime_line = output
            .lines()
            .find(|l| l.starts_with("UPTIME:"))
            .unwrap_or("");
        assert!(
            !uptime_line.contains("No such file"),
            "uptime leaked an error: {}",
            uptime_line
        );
    }

    /// Real-world recon payload that uses multi-line `if`/`then`/`fi` control
    /// flow and `${var:+word}` parameter expansion. Fed line-by-line with block
    /// buffering, exactly as the honeypot receives it interactively.
    #[tokio::test]
    async fn real_recon_if_block_script() {
        let script = r#"export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
uname=$(uname -s -v -n -m 2>/dev/null)
arch=$(uname -m 2>/dev/null)
uptime=$(awk '{u=int($1);d=int(u/86400);h=int((u%86400)/3600);m=int((u%3600)/60);s="";if(d>0)s=s d"d";if(h>0){if(s!="")s=s", ";s=s h"h"}if(m>0||s==""){if(s!="")s=s", ";s=s m"m"}print s}' /proc/uptime 2>/dev/null)
if [ -z "$uptime" ]; then
	secondsStr=$(cat /proc/uptime 2>/dev/null | cut -d' ' -f1 | cut -d. -f1)
	if [ -n "$secondsStr" ]; then
		seconds=$((secondsStr))
		d=$((seconds/86400))
		h=$(( (seconds%86400)/3600 ))
		m=$(( (seconds%3600)/60 ))
		uptime=""
		[ $d -gt 0 ] && uptime="${uptime}${d}d"
		[ $h -gt 0 ] && uptime="${uptime:+$uptime, }${h}h"
		[ $m -gt 0 ] && uptime="${uptime:+$uptime, }${m}m"
		[ -z "$uptime" ] && uptime="0m"
	fi
fi
cpus=$( (nproc || grep -c "^processor" /proc/cpuinfo 2>/dev/null) | head -1)
cpu_model=$( (grep -m1 "model name" /proc/cpuinfo 2>/dev/null || lscpu 2>/dev/null | grep -m1 "Model name") | cut -d: -f2 | sed 's/^ //;s/ *$//')
gpu_info=$(( (lspci 2>/dev/null | grep -i vga; lspci 2>/dev/null | grep -i nvidia) | head -n50 ))
cat_help=$(cat --help 2>&1 | tr '\n' ' ' || cat --help 2>&1)
ls_help=$(ls --help 2>&1 | tr '\n' ' ' || ls --help 2>&1)
last_output=$(last 2>/dev/null | head -n 10)
echo "UNAME:$uname"
echo "ARCH:$arch"
echo "UPTIME:$uptime"
echo "CPUS:$cpus"
echo "CPU_MODEL:$cpu_model"
echo "GPU:$gpu_info"
echo "CAT_HELP:$cat_help"
echo "LS_HELP:$ls_help"
echo "LAST:$last_output"
"#;

        let d = make_dispatcher();
        let mut ctx = make_context();

        // Buffer lines until the block is complete, then execute — mirroring
        // the honeypot's interactive multi-line handling.
        let mut output = String::new();
        let mut pending = String::new();
        for line in script.lines() {
            if !pending.is_empty() {
                pending.push('\n');
            }
            pending.push_str(line);
            if parser::is_incomplete_block(&pending) {
                continue;
            }
            if pending.trim().is_empty() {
                pending.clear();
                continue;
            }
            let out = d.execute(&pending, &mut ctx).await;
            output.push_str(&out.output);
            pending.clear();
        }
        if !pending.trim().is_empty() {
            let out = d.execute(&pending, &mut ctx).await;
            output.push_str(&out.output);
        }

        // All nine fingerprint markers present.
        for marker in [
            "UNAME:",
            "ARCH:",
            "UPTIME:",
            "CPUS:",
            "CPU_MODEL:",
            "GPU:",
            "CAT_HELP:",
            "LS_HELP:",
            "LAST:",
        ] {
            assert!(
                output.contains(marker),
                "missing marker {:?}:\n{}",
                marker,
                output
            );
        }

        // Command substitution worked.
        assert!(output.contains("UNAME:Linux"), "uname failed:\n{}", output);
        assert!(output.contains("ARCH:x86_64"), "arch failed:\n{}", output);

        // Control-flow keywords must NOT leak as "command not found".
        for bad in [
            "if: command not found",
            "then: command not found",
            "fi: command not found",
            "else: command not found",
            "export: command not found",
        ] {
            assert!(!output.contains(bad), "leaked {:?}:\n{}", bad, output);
        }
    }

    #[tokio::test]
    async fn true_exit_code_zero() {
        let d = make_dispatcher();
        let mut ctx = make_context();
        let out = d.execute("true", &mut ctx).await;
        assert_eq!(out.exit_code, 0);
        assert!(!out.exit_requested);
    }

    #[tokio::test]
    async fn false_exit_code_one() {
        let d = make_dispatcher();
        let mut ctx = make_context();
        let out = d.execute("false", &mut ctx).await;
        assert_eq!(out.exit_code, 1);
        assert!(!out.exit_requested);
    }

    #[tokio::test]
    async fn command_not_found_exit_127() {
        let d = make_dispatcher();
        let mut ctx = make_context();
        let out = d.execute("nosuchcmd123", &mut ctx).await;
        assert_eq!(out.exit_code, 127);
        assert!(out.output.contains("command not found"));
    }

    #[tokio::test]
    async fn path_command_not_found_exit_127() {
        let d = make_dispatcher();
        let mut ctx = make_context();
        let out = d.execute("/nonexistent/dir/tool", &mut ctx).await;
        assert_eq!(out.exit_code, 127);
        assert!(out.output.contains("No such file or directory"));
    }

    #[tokio::test]
    async fn failing_command_propagates_code() {
        let d = make_dispatcher();
        let mut ctx = make_context();
        let out = d.execute("cat /does/not/exist", &mut ctx).await;
        assert_eq!(out.exit_code, 1);
    }

    #[tokio::test]
    async fn dollar_question_same_line_false_then_echo() {
        let d = make_dispatcher();
        let mut ctx = make_context();
        let out = d.execute("false; echo $?", &mut ctx).await;
        assert_eq!(out.exit_code, 0, "echo succeeds");
        assert!(
            out.output.contains("\n1\r\n") || out.output.contains("1\r\n"),
            "got: {:?}",
            out.output
        );
    }

    #[tokio::test]
    async fn dollar_question_expands_zero_after_success() {
        let d = make_dispatcher();
        let mut ctx = make_context();
        let out = d.execute("true; echo $?", &mut ctx).await;
        assert!(out.output.contains("0\r\n"), "got: {:?}", out.output);
    }

    #[tokio::test]
    async fn dollar_question_brace_form() {
        let d = make_dispatcher();
        let mut ctx = make_context();
        let out = d.execute("false; echo ${?}", &mut ctx).await;
        assert!(out.output.contains("1\r\n"), "got: {:?}", out.output);
    }

    #[tokio::test]
    async fn dollar_question_across_lines() {
        let d = make_dispatcher();
        let mut ctx = make_context();
        let out = d.execute("false", &mut ctx).await;
        assert_eq!(out.exit_code, 1);
        let out2 = d.execute("echo status=$?", &mut ctx).await;
        assert!(out2.output.contains("status=1"), "got: {:?}", out2.output);
    }

    #[tokio::test]
    async fn andor_or_takes_right_branch_on_failure() {
        let d = make_dispatcher();
        let mut ctx = make_context();
        let out = d.execute("false && echo yes || echo no", &mut ctx).await;
        assert!(!out.output.contains("yes\r\n"));
        assert!(out.output.contains("no\r\n"));
        assert_eq!(out.exit_code, 0);
    }

    #[tokio::test]
    async fn andor_failing_or_chain_reports_code() {
        let d = make_dispatcher();
        let mut ctx = make_context();
        let out = d.execute("nosuchcmd || false", &mut ctx).await;
        assert_eq!(out.exit_code, 1);
    }

    #[tokio::test]
    async fn exit_with_numeric_argument() {
        let d = make_dispatcher();
        let mut ctx = make_context();
        let out = d.execute("exit 5", &mut ctx).await;
        assert!(out.exit_requested);
        assert_eq!(out.exit_code, 5);
        assert!(
            !out.output.contains("numeric"),
            "no error expected: {:?}",
            out.output
        );
    }

    #[tokio::test]
    async fn exit_with_non_numeric_argument() {
        let d = make_dispatcher();
        let mut ctx = make_context();
        let out = d.execute("exit abc", &mut ctx).await;
        assert!(out.exit_requested);
        assert_eq!(out.exit_code, 2);
        assert!(out.output.contains("numeric argument required"));
    }

    #[tokio::test]
    async fn exit_without_argument_uses_last_status() {
        let d = make_dispatcher();
        let mut ctx = make_context();
        let out = d.execute("false; exit", &mut ctx).await;
        assert!(out.exit_requested);
        assert_eq!(out.exit_code, 1);
    }

    #[tokio::test]
    async fn exit_status_wraps_to_u8() {
        let d = make_dispatcher();
        let mut ctx = make_context();
        let out = d.execute("exit 300", &mut ctx).await;
        assert_eq!(out.exit_code, 300 & 0xFF);
    }

    #[tokio::test]
    async fn filter_no_match_exit_one() {
        let d = make_dispatcher();
        let mut ctx = make_context();
        let out = d
            .execute("echo hello | grep -q nonexistent", &mut ctx)
            .await;
        assert_eq!(out.exit_code, 1);
    }

    #[tokio::test]
    async fn pipeline_status_is_last_stage() {
        let d = make_dispatcher();
        let mut ctx = make_context();
        let out = d.execute("echo hello | grep -q hello", &mut ctx).await;
        assert_eq!(out.exit_code, 0);
    }

    #[tokio::test]
    async fn bare_assignment_exit_zero() {
        let d = make_dispatcher();
        let mut ctx = make_context();
        let out = d.execute("FOO=bar", &mut ctx).await;
        assert_eq!(out.exit_code, 0);
    }

    #[tokio::test]
    async fn assignment_prefix_command_code() {
        let d = make_dispatcher();
        let mut ctx = make_context();
        let out = d.execute("FOO=bar false", &mut ctx).await;
        assert_eq!(out.exit_code, 1);
    }

    #[tokio::test]
    async fn exit_in_middle_of_pipeline_suppresses_later_stages() {
        let d = make_dispatcher();
        let mut ctx = make_context();
        let out = d.execute("exit 7; echo unreachable", &mut ctx).await;
        assert_eq!(out.exit_code, 7);
        assert!(!out.output.contains("unreachable"));
    }

    #[tokio::test]
    async fn andor_first_status_visible_in_branch() {
        // bash: `false || echo $?` prints 1 (the status of the failed left side).
        let d = make_dispatcher();
        let mut ctx = make_context();
        let out = d.execute("false || echo $?", &mut ctx).await;
        assert!(
            out.output.contains("\n1\r\n") || out.output.trim_end().ends_with('1'),
            "got: {:?}",
            out.output
        );
        assert_eq!(out.exit_code, 0);
    }

    #[tokio::test]
    async fn dollar_question_in_command_args() {
        let d = make_dispatcher();
        let mut ctx = make_context();
        let out = d.execute("false; echo status-$?", &mut ctx).await;
        assert!(out.output.contains("status-1"), "got: {:?}", out.output);
    }
}
