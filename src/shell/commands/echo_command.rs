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
        \\xHH   byte with hexadecimal value HH (1 to 2 digits)\n".to_string()
    }
    
    fn version(&self) -> String {
        "echo (GNU coreutils) 8.32\n\
        License GPLv3+: GNU GPL version 3 or later <https://gnu.org/licenses/gpl.html>.\n\
        This is free software: you are free to change and redistribute it.\n\
        There is NO WARRANTY, to the extent permitted by law.\n".to_string()
    }
    
    async fn execute(&self, args: &str, _context: &mut CommandContext) -> CommandResult {
        let mut args = args.trim();
        
        // Default settings
        let mut new_line = true;
        let mut enable_escapes = false;
        let mut no_space_output = false;
        let mut print_help = false;
        let mut print_version = false;
        
        // Parse flags until we hit a non-flag or '--' delimiter
        while !args.is_empty() && args.starts_with('-') {
            if args.starts_with("--") {
                if args == "--" {
                    args = ""; // Just -- with nothing after it
                    break;
                } else if args.starts_with("--help") {
                    print_help = true;
                    break;
                } else if args.starts_with("--version") {
                    print_version = true;
                    break;
                } else if args.starts_with("--enable-escapes") || args.starts_with("--escape") {
                    enable_escapes = true;
                    args = args["--enable-escapes".len()..].trim_start();
                } else if args.starts_with("--disable-escapes") {
                    enable_escapes = false;
                    args = args["--disable-escapes".len()..].trim_start();
                } else if args.starts_with("--no-newline") || args.starts_with("--newline=") {
                    new_line = false;
                    if args.starts_with("--no-newline") {
                        args = args["--no-newline".len()..].trim_start();
                    } else {
                        // Handle --newline=yes|no
                        let option = &args["--newline=".len()..];
                        if option.starts_with("yes") {
                            new_line = true;
                            args = option["yes".len()..].trim_start();
                        } else if option.starts_with("no") {
                            new_line = false;
                            args = option["no".len()..].trim_start();
                        } else {
                            // Invalid option - treat the rest as a string to echo
                            break;
                        }
                    }
                } else {
                    // Unknown long option - treat the rest as a string to echo
                    break;
                }
            } else {
                // Short options can be combined (like -ne)
                let options = &args[1..]; // Skip the '-'
                let mut option_len = 1; // Include the '-'
                
                for c in options.chars() {
                    option_len += 1;
                    match c {
                        'n' => new_line = false,
                        'e' => enable_escapes = true,
                        'E' => enable_escapes = false,
                        's' => no_space_output = true,
                        'h' => { print_help = true; break; }
                        'v' => { print_version = true; break; }
                        _ => {
                            // Unknown option - Stop parsing and treat the rest as strings
                            option_len -= 1; // Don't include this character in what we skip
                            break;
                        }
                    }
                }
                
                args = args[option_len..].trim_start();
            }
        }
        
        // Handle special print modes
        if print_help {
            return Ok(self.help());
        }
        
        if print_version {
            return Ok(self.version());
        }
        
        // Process the arguments
        if args.is_empty() {
            // Echo with no args gives just a newline
            return Ok(if new_line { "\r\n".to_string() } else { "".to_string() });
        }
        
        // Split the arguments - we need to handle quoted arguments properly
        let mut processed_output = String::new();
        let mut current_arg = String::new();
        
        // Simplified argument parsing
        let mut in_single_quotes = false;
        let mut in_double_quotes = false;
        let mut i = 0;
        let chars: Vec<char> = args.chars().collect();
        
        while i < chars.len() {
            let c = chars[i];
            
            match c {
                '\'' if !in_double_quotes => {
                    in_single_quotes = !in_single_quotes;
                },
                '"' if !in_single_quotes => {
                    in_double_quotes = !in_double_quotes;
                },
                ' ' if !in_single_quotes && !in_double_quotes => {
                    // Space outside quotes marks end of current argument
                    if !current_arg.is_empty() || !no_space_output {
                        if !processed_output.is_empty() && !no_space_output {
                            processed_output.push(' ');
                        }
                        processed_output.push_str(&current_arg);
                        current_arg.clear();
                    }
                },
                '\\' if (enable_escapes && !in_single_quotes) && i + 1 < chars.len() => {
                    // Handle escape sequences
                    i += 1;
                    match chars[i] {
                        '\\' => current_arg.push('\\'),
                        'a' => current_arg.push('\x07'), // Bell
                        'b' => current_arg.push('\x08'), // Backspace
                        'c' => {
                            // \c means stop output immediately
                            if !processed_output.is_empty() && !current_arg.is_empty() {
                                if !no_space_output {
                                    processed_output.push(' ');
                                }
                                processed_output.push_str(&current_arg);
                            }
                            return Ok(processed_output); // Return without newline
                        },
                        'e' => current_arg.push('\x1B'), // Escape
                        'f' => current_arg.push('\x0C'), // Form feed
                        'n' => current_arg.push('\n'),
                        'r' => current_arg.push('\r'),
                        't' => current_arg.push('\t'),
                        'v' => current_arg.push('\x0B'), // Vertical tab
                        'x' => {
                            // Hex value (up to 2 digits)
                            let mut hex_val = String::new();
                            let mut j = 1;
                            while i + j < chars.len() && j <= 2 && chars[i + j].is_ascii_hexdigit() {
                                hex_val.push(chars[i + j]);
                                j += 1;
                            }
                            if !hex_val.is_empty() {
                                if let Ok(val) = u8::from_str_radix(&hex_val, 16) {
                                    current_arg.push(val as char);
                                }
                                i += hex_val.len();
                            } else {
                                current_arg.push('x'); // No valid hex digits
                            }
                            i -= 1; // Compensate for the additional increment at the end
                        },
                        '0' => {
                            // Octal value (up to 3 digits)
                            let mut octal_val = String::new();
                            let mut j = 0;
                            while i + j < chars.len() && j < 3 && chars[i + j].is_digit(8) {
                                octal_val.push(chars[i + j]);
                                j += 1;
                            }
                            if !octal_val.is_empty() {
                                if let Ok(val) = u8::from_str_radix(&octal_val, 8) {
                                    current_arg.push(val as char);
                                }
                                i += octal_val.len() - 1; // -1 for the '0' we've already processed
                            } else {
                                current_arg.push('0');
                            }
                            i -= 1; // Compensate for the additional increment at the end
                        },
                        _ => current_arg.push(chars[i]), // Other escapes just print the char
                    }
                },
                _ => current_arg.push(c),
            }
            i += 1;
        }
        
        // Add the last argument
        if !current_arg.is_empty() {
            if !processed_output.is_empty() && !no_space_output {
                processed_output.push(' ');
            }
            processed_output.push_str(&current_arg);
        }
        
        // Add newline if needed
        if new_line {
            processed_output.push_str("\r\n");
        }
        
        Ok(processed_output)
    }
}