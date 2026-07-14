use super::command_trait::{Command, CommandResult};
use super::context::CommandContext;
use async_trait::async_trait;

/// Echo command implementation using the new trait system
pub struct EchoCommand;

#[async_trait]
impl Command for EchoCommand {
    fn name(&self) -> &'static str {
        "echo"
    }

    fn help(&self) -> String {
        "Usage: echo [OPTION]... [STRING]...\n\
        Echo the STRING(s) to standard output.\n\
        \n\
        Mandatory arguments to long options are mandatory for short options too.\n\
        -n             do not output the trailing newline\n\
        -e             enable interpretation of backslash escapes\n\
        -E             disable interpretation of backslash escapes (default)\n\
        -s             do not separate arguments with spaces\n\
        --help         display this help and exit\n\
        --version      output version information and exit\n\
        \n\
        If -e is in effect, the following sequences are recognized:\n\
        \\\\     backslash\n\
        \\a     alert (BEL)\n\
        \\b     backspace\n\
        \\c     produce no further output\n\
        \\e     escape\n\
        \\f     form feed\n\
        \\n     new line\n\
        \\r     carriage return\n\
        \\t     horizontal tab\n\
        \\v     vertical tab\n\
        \\0NNN  byte with octal value NNN (1 to 3 digits)\n\
        \\xHH   byte with hexadecimal value HH (1 to 2 digits)\n"
            .to_string()
    }

    fn version(&self) -> String {
        "echo (GNU coreutils) 8.32\n\
        License GPLv3+: GNU GPL version 3 or later <https://gnu.org/licenses/gpl.html>.\n\
        This is free software: you are free to change and redistribute it.\n\
        There is NO WARRANTY, to the extent permitted by law.\n"
            .to_string()
    }

    async fn execute(&self, args: &[String], _context: &mut CommandContext) -> CommandResult {
        let mut new_line = true;
        let mut enable_escapes = false;
        let mut no_space_output = false;
        let mut print_help = false;
        let mut print_version = false;

        let mut idx = 0;
        while idx < args.len() {
            let arg = &args[idx];
            if arg == "--help" {
                print_help = true;
                break;
            }
            if arg == "--version" {
                print_version = true;
                break;
            }
            if arg == "--" {
                idx += 1;
                break;
            }
            if arg == "--enable-escapes" || arg == "--escape" {
                enable_escapes = true;
                idx += 1;
                continue;
            }
            if arg == "--disable-escapes" {
                enable_escapes = false;
                idx += 1;
                continue;
            }
            if arg == "--no-newline" {
                new_line = false;
                idx += 1;
                continue;
            }
            if let Some(flags) = arg.strip_prefix('-') {
                if flags.is_empty() {
                    break;
                }
                let mut consumed_all = true;
                for c in flags.chars() {
                    match c {
                        'n' => new_line = false,
                        'e' => enable_escapes = true,
                        'E' => enable_escapes = false,
                        's' => no_space_output = true,
                        'h' => {
                            print_help = true;
                        }
                        'v' => {
                            print_version = true;
                        }
                        _ => {
                            consumed_all = false;
                            break;
                        }
                    }
                }
                if consumed_all {
                    idx += 1;
                    continue;
                } else {
                    break;
                }
            }
            break;
        }

        if print_help {
            return Ok(self.help());
        }

        if print_version {
            return Ok(self.version());
        }

        let strings: &[String] = &args[idx..];

        if strings.is_empty() {
            return Ok(if new_line {
                "\r\n".to_string()
            } else {
                String::new()
            });
        }

        let mut processed: Vec<String> = Vec::with_capacity(strings.len());
        for (n, s) in strings.iter().enumerate() {
            let interpreted = if enable_escapes {
                interpret_escapes(s)
            } else {
                s.clone()
            };
            if let Some(stripped) = interpreted.strip_suffix('\x00') {
                processed.push(stripped.to_string());
                break;
            }
            if interpreted.contains('\x00') {
                let (head, _) = interpreted.split_once('\x00').unwrap();
                processed.push(head.to_string());
                break;
            }
            let _ = n;
            processed.push(interpreted);
        }

        let separator = if no_space_output { "" } else { " " };
        let mut output = processed.join(separator);

        if new_line {
            output.push_str("\r\n");
        }

        Ok(output)
    }
}

/// Interpret backslash escape sequences (used by `echo -e`).
fn interpret_escapes(input: &str) -> String {
    let chars: Vec<char> = input.chars().collect();
    let mut out = String::new();
    let mut i = 0;
    while i < chars.len() {
        let c = chars[i];
        if c != '\\' {
            out.push(c);
            i += 1;
            continue;
        }
        let Some(&next) = chars.get(i + 1) else {
            out.push('\\');
            i += 1;
            continue;
        };
        match next {
            '\\' => out.push('\\'),
            'a' => out.push('\x07'),
            'b' => out.push('\x08'),
            'c' => {
                out.push('\x00');
                i += 2;
                continue;
            }
            'e' => out.push('\x1B'),
            'f' => out.push('\x0C'),
            'n' => out.push('\n'),
            'r' => out.push('\r'),
            't' => out.push('\t'),
            'v' => out.push('\x0B'),
            'x' => {
                let mut hex = String::new();
                let mut j = 1;
                while i + 1 + j < chars.len() && j <= 2 && chars[i + 1 + j].is_ascii_hexdigit() {
                    hex.push(chars[i + 1 + j]);
                    j += 1;
                }
                if let Ok(val) = u8::from_str_radix(&hex, 16) {
                    out.push(val as char);
                } else {
                    out.push('\\');
                    out.push('x');
                }
                i += 1 + hex.len();
                continue;
            }
            '0' => {
                let mut oct = String::new();
                let mut j = 1;
                while i + 1 + j < chars.len() && j <= 3 && chars[i + 1 + j].is_digit(8) {
                    oct.push(chars[i + 1 + j]);
                    j += 1;
                }
                if let Ok(val) = u8::from_str_radix(&oct, 8) {
                    out.push(val as char);
                } else {
                    out.push('\\');
                    out.push('0');
                }
                i += 1 + oct.len();
                continue;
            }
            other => {
                out.push('\\');
                out.push(other);
            }
        }
        i += 2;
    }
    out
}
