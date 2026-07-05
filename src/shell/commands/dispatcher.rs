use super::command_trait::CommandError;
use super::context::CommandContext;
use super::registry::CommandRegistry;
use crate::shell::filters;
use crate::shell::parser::{self, AndOp, CommandList, Redirect};
use std::future::Future;
use std::pin::Pin;

/// Outcome of executing a full command line.
pub struct ExecutionOutcome {
    /// Text to display to the client.
    pub output: String,
    /// Whether the user requested the session to end (`exit` / `logout`).
    pub exit_requested: bool,
}

/// Handles command parsing and execution.
pub struct CommandDispatcher {
    registry: CommandRegistry,
}

/// Internal result of running a single pipeline.
struct PipeResult {
    stdout: String,
    stderr: String,
    success: bool,
    exit_requested: bool,
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
            };
        }

        let resolved = self.resolve_substitutions(command_line, context).await;
        if resolved.trim().is_empty() {
            return ExecutionOutcome {
                output: String::new(),
                exit_requested: false,
            };
        }

        let home = context
            .get_env("HOME")
            .cloned()
            .unwrap_or_else(|| format!("/home/{}", context.username));
        let script = parser::parse_script(&resolved, &context.env_vars, &home);

        let (stdout, stderr, exit, _) = self.run_nodes(&script.nodes, context).await;
        let mut output = stdout;
        output.push_str(&stderr);

        ExecutionOutcome {
            output,
            exit_requested: exit,
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
    /// Returns `(stdout, stderr, exit_requested, last_success)`.
    async fn run_command_list(
        &self,
        list: &CommandList,
        context: &mut CommandContext,
    ) -> (String, String, bool, bool) {
        let mut stdout = String::new();
        let mut stderr = String::new();
        let mut exit = false;
        let mut last_success = true;
        let mut should_run = true;

        for item in &list.items {
            if should_run {
                let r = self.run_pipeline(&item.pipeline, context).await;
                stdout.push_str(&r.stdout);
                stderr.push_str(&r.stderr);
                exit |= r.exit_requested;
                last_success = r.success;
            }
            should_run = match item.op {
                AndOp::Then => true,
                AndOp::And => last_success,
                AndOp::Or => !last_success,
            };
        }

        (stdout, stderr, exit, last_success)
    }

    /// Run a sequence of parsed nodes (control flow + command lists).
    /// Returns `(stdout, stderr, exit_requested, last_success)`.
    /// Boxed to break the async recursion cycle with `run_node` (nested control
    /// flow like `if` inside `if`).
    fn run_nodes<'a>(
        &'a self,
        nodes: &'a [parser::Node],
        context: &'a mut CommandContext,
    ) -> Pin<Box<dyn Future<Output = (String, String, bool, bool)> + Send + 'a>> {
        Box::pin(async move {
            let mut stdout = String::new();
            let mut stderr = String::new();
            let mut exit = false;
            let mut last_success = true;
            for node in nodes {
                let (o, e, ex, succ) = self.run_node(node, context).await;
                stdout.push_str(&o);
                stderr.push_str(&e);
                exit |= ex;
                last_success = succ;
                if exit {
                    break;
                }
            }
            (stdout, stderr, exit, last_success)
        })
    }

    /// Execute a single parsed node. Returns `(stdout, stderr, exit, success)`.
    async fn run_node(
        &self,
        node: &parser::Node,
        context: &mut CommandContext,
    ) -> (String, String, bool, bool) {
        match node {
            parser::Node::Seq(list) => self.run_command_list(list, context).await,
            parser::Node::If {
                branches,
                else_body,
            } => {
                let mut stdout = String::new();
                let mut stderr = String::new();
                for (cond, body) in branches {
                    let (o, e, _ex, succ) = self.run_nodes(cond, context).await;
                    stdout.push_str(&o);
                    stderr.push_str(&e);
                    if succ {
                        let (o2, e2, ex2, _) = self.run_nodes(body, context).await;
                        stdout.push_str(&o2);
                        stderr.push_str(&e2);
                        return (stdout, stderr, ex2, true);
                    }
                }
                if let Some(els) = else_body {
                    let (o, e, ex, _) = self.run_nodes(els, context).await;
                    stdout.push_str(&o);
                    stderr.push_str(&e);
                    return (stdout, stderr, ex, true);
                }
                (stdout, stderr, false, true)
            }
            parser::Node::For { var, words, body } => {
                let mut stdout = String::new();
                let mut stderr = String::new();
                let mut exit = false;
                let mut last_success = true;
                let saved = context.env_vars.get(var).cloned();
                for w in words {
                    context.env_vars.insert(var.clone(), w.clone());
                    let (o, e, ex, succ) = self.run_nodes(body, context).await;
                    stdout.push_str(&o);
                    stderr.push_str(&e);
                    exit |= ex;
                    last_success = succ;
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
                (stdout, stderr, exit, last_success)
            }
            parser::Node::While { cond, body, until } => {
                let mut stdout = String::new();
                let mut stderr = String::new();
                let mut exit = false;
                for _ in 0..10000 {
                    let (_o, _e, _ex, succ) = self.run_nodes(cond, context).await;
                    let keep_going = if *until { !succ } else { succ };
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
                (stdout, stderr, exit, true)
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
        let mut success = true;
        let mut exit_requested = false;

        for (idx, cmd) in pipeline.commands.iter().enumerate() {
            if cmd.name.is_empty() {
                continue;
            }
            if cmd.name == "exit" || cmd.name == "logout" {
                exit_requested = true;
                break;
            }

            let is_first = idx == 0;
            let stdin = if is_first {
                String::new()
            } else {
                stdout.clone()
            };

            // Bare variable assignment `VAR=value` (RHS already expanded).
            if let Some((var, val)) = parser::parse_assignment(&cmd.name) {
                context.env_vars.insert(var, val);
                if cmd.args.is_empty() {
                    success = true;
                    continue;
                }
                // `VAR=value command args`: set env var then run the real command.
                let real_name = cmd.args[0].clone();
                let real_args: Vec<String> = cmd.args[1..].to_vec();
                let (mut out, mut err, succ) = self
                    .dispatch_one(&real_name, &real_args, &stdin, is_first, context)
                    .await;
                Self::apply_redirects(&mut out, &mut err, &cmd.redirects);
                stdout = out;
                stderr_acc.push_str(&err);
                success = succ;
                continue;
            }

            let (mut out, mut err, succ) = self
                .dispatch_one(&cmd.name, &cmd.args, &stdin, is_first, context)
                .await;
            Self::apply_redirects(&mut out, &mut err, &cmd.redirects);
            stdout = out;
            stderr_acc.push_str(&err);
            success = succ;
        }

        PipeResult {
            stdout,
            stderr: stderr_acc,
            success,
            exit_requested,
        }
    }

    /// Dispatch a single command/filter, returning `(stdout, stderr, success)`.
    async fn dispatch_one(
        &self,
        name: &str,
        args: &[String],
        stdin: &str,
        is_first: bool,
        context: &mut CommandContext,
    ) -> (String, String, bool) {
        if name.is_empty() {
            return (String::new(), String::new(), true);
        }
        if filters::is_filter(name) && (!is_first || !self.registry.has_command(name)) {
            match filters::apply_filter(name, args, stdin, context).await {
                Some((out, succ)) => (out, String::new(), succ),
                None => (
                    String::new(),
                    format!("bash: {}: command not found\r\n", name),
                    false,
                ),
            }
        } else if self.registry.has_command(name) {
            match self.registry.execute_command(name, args, context).await {
                Ok(out) => (out, String::new(), true),
                Err(e) => {
                    let succ = matches!(e, CommandError::SilentFailure);
                    let msg = format!("{}\r\n", e);
                    (String::new(), msg, succ)
                }
            }
        } else {
            (
                String::new(),
                format!("bash: {}: command not found\r\n", name),
                false,
            )
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
    use crate::shell::commands::{
        CatCommand, ColonCommand, DateCommand, EchoCommand, ExitCommand, ExportCommand,
        FalseCommand, LsCommand, TestCommand, TrueCommand, UnameCommand, UnsetCommand,
    };
    use crate::shell::filesystem::fs2::FileSystem;
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
}
