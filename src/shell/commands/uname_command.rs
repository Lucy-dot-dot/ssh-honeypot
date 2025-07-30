use async_trait::async_trait;
use super::command_trait::{Command, CommandResult};
use super::context::CommandContext;

/// Uname command implementation using the new trait system
pub struct UnameCommand;

#[async_trait]
impl Command for UnameCommand {
    fn name(&self) -> &'static str {
        "uname"
    }
    
    fn help(&self) -> String {
        "Usage: uname [OPTION]...\n\
        Print certain system information.  With no OPTION, same as -s.\n\
        \n\
        -a, --all                print all information, in the following order,\n\
                                  except omit -p and -i if unknown:\n\
        -s, --kernel-name        print the kernel name\n\
        -n, --nodename           print the network node hostname\n\
        -r, --kernel-release     print the kernel release\n\
        -v, --kernel-version     print the kernel version\n\
        -m, --machine            print the machine hardware name\n\
        -p, --processor          print the processor type (non-portable)\n\
        -i, --hardware-platform  print the hardware platform (non-portable)\n\
        -o, --operating-system   print the operating system\n\
        --help                   display this help and exit\n\
        --version                output version information and exit\n".to_string()
    }
    
    fn version(&self) -> String {
        "uname (GNU coreutils) 8.32\n\
        License GPLv3+: GNU GPL version 3 or later <https://gnu.org/licenses/gpl.html>.\n\
        This is free software: you are free to change and redistribute it.\n\
        There is NO WARRANTY, to the extent permitted by law.\n".to_string()
    }
    
    async fn execute(&self, args: &str, context: &mut CommandContext) -> CommandResult {
        // Handle help and version flags
        if args.contains("--help") {
            return Ok(self.help());
        }
        
        if args.contains("--version") {
            return Ok(self.version());
        }
        
        let hostname = &context.hostname;
        
        // Default values for system information
        let kernel_name = "Linux";
        let kernel_release = "5.4.0-109-generic";
        let kernel_version = "#123-Ubuntu SMP Fri Apr 8 09:10:54 UTC 2022";
        let machine = "x86_64";
        let processor = "x86_64";
        let hardware_platform = "x86_64";
        let operating_system = "GNU/Linux";
        
        let mut output_parts = Vec::new();
        
        // Parse arguments
        let args = args.trim();
        
        if args.is_empty() || args.contains("-s") || args.contains("--kernel-name") {
            output_parts.push(kernel_name);
        }
        
        if args.contains("-a") || args.contains("--all") {
            // Print all information
            output_parts.clear();
            output_parts.extend(&[
                kernel_name,
                hostname,
                kernel_release,
                kernel_version,
                machine,
                processor,
                hardware_platform,
                operating_system,
            ]);
        } else {
            // Handle individual flags
            if args.contains("-n") || args.contains("--nodename") {
                if !output_parts.contains(&hostname.as_str()) {
                    output_parts.push(hostname);
                }
            }
            if args.contains("-r") || args.contains("--kernel-release") {
                if !output_parts.contains(&kernel_release) {
                    output_parts.push(kernel_release);
                }
            }
            if args.contains("-v") || args.contains("--kernel-version") {
                if !output_parts.contains(&kernel_version) {
                    output_parts.push(kernel_version);
                }
            }
            if args.contains("-m") || args.contains("--machine") {
                if !output_parts.contains(&machine) {
                    output_parts.push(machine);
                }
            }
            if args.contains("-p") || args.contains("--processor") {
                if !output_parts.contains(&processor) {
                    output_parts.push(processor);
                }
            }
            if args.contains("-i") || args.contains("--hardware-platform") {
                if !output_parts.contains(&hardware_platform) {
                    output_parts.push(hardware_platform);
                }
            }
            if args.contains("-o") || args.contains("--operating-system") {
                if !output_parts.contains(&operating_system) {
                    output_parts.push(operating_system);
                }
            }
        }
        
        // If no flags matched, default to kernel name
        if output_parts.is_empty() {
            output_parts.push(kernel_name);
        }
        
        Ok(format!("{}\r\n", output_parts.join(" ")))
    }
}