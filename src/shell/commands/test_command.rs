use async_trait::async_trait;
use super::command_trait::{Command, CommandError, CommandResult};
use super::context::CommandContext;
use crate::shell::filesystem::fs2::FileContent;

/// The shell `test` / `[` builtin. Returns success (Ok) when the condition is
/// true, `SilentFailure` (exit 1, no output) when false.
pub struct TestCommand;

fn to_i(s: &str) -> i64 {
    s.trim().parse::<i64>().unwrap_or(0)
}

#[async_trait]
impl Command for TestCommand {
    fn name(&self) -> &'static str {
        "["
    }

    fn aliases(&self) -> Vec<&'static str> {
        vec!["test"]
    }

    async fn execute(&self, args: &[String], context: &mut CommandContext) -> CommandResult {
        let mut a: Vec<String> = args.to_vec();
        // Drop the trailing "]" argument that `[ ... ]` requires.
        if a.last().map(|s| s.as_str()) == Some("]") {
            a.pop();
        }

        let ok = eval_test(&a, context).await;
        if ok {
            Ok(String::new())
        } else {
            Err(CommandError::SilentFailure)
        }
    }
}

async fn eval_test(a: &[String], context: &mut CommandContext) -> bool {
    match a.len() {
        0 => false,
        1 => !a[0].is_empty(),
        2 => match a[0].as_str() {
            "-z" => a[1].is_empty(),
            "-n" => !a[1].is_empty(),
            "!" => !eval_inner_sync(&a[1..]),
            "-e" | "-f" | "-d" | "-r" | "-s" | "-w" | "-x" => path_check(&a[0], &a[1], context).await,
            _ => false,
        },
        3 => {
            let (l, op, r) = (&a[0], &a[1], &a[2]);
            match op.as_str() {
                "=" | "==" => l == r,
                "!=" => l != r,
                "-eq" => to_i(l) == to_i(r),
                "-ne" => to_i(l) != to_i(r),
                "-gt" => to_i(l) > to_i(r),
                "-ge" => to_i(l) >= to_i(r),
                "-lt" => to_i(l) < to_i(r),
                "-le" => to_i(l) <= to_i(r),
                _ => false,
            }
        }
        _ => {
            if a[0] == "!" {
                return !eval_inner_sync(&a[1..]);
            }
            false
        }
    }
}

/// Synchronous subset of the evaluator (used by `!` negation).
fn eval_inner_sync(a: &[String]) -> bool {
    match a.len() {
        0 => false,
        1 => !a[0].is_empty(),
        2 => matches!(a[0].as_str(), "-z") && a[1].is_empty()
            || matches!(a[0].as_str(), "-n") && !a[1].is_empty(),
        3 => {
            let (l, op, r) = (&a[0], &a[1], &a[2]);
            match op.as_str() {
                "=" | "==" => l == r,
                "!=" => l != r,
                "-eq" => to_i(l) == to_i(r),
                "-ne" => to_i(l) != to_i(r),
                "-gt" => to_i(l) > to_i(r),
                "-ge" => to_i(l) >= to_i(r),
                "-lt" => to_i(l) < to_i(r),
                "-le" => to_i(l) <= to_i(r),
                _ => false,
            }
        }
        _ => false,
    }
}

/// File-existence/type checks against the virtual filesystem.
async fn path_check(op: &str, path: &str, context: &mut CommandContext) -> bool {
    let fs = context.filesystem.read().await;
    let entry = match fs.follow_symlink(path) {
        Ok(e) => e,
        Err(_) => return false,
    };
    let Some(content) = entry.file_content.as_ref() else {
        return matches!(op, "-e");
    };
    match op {
        "-e" => true,
        "-f" => matches!(content, FileContent::RegularFile(_)),
        "-d" => matches!(content, FileContent::Directory(_)),
        "-s" => matches!(content, FileContent::RegularFile(b) if !b.is_empty()),
        "-r" | "-w" | "-x" => true,
        _ => false,
    }
}
