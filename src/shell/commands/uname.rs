use chrono::{Local, Datelike};
use rand::{Rng, rng};

/// Kernel information structure for uname
#[derive(Clone)]
pub struct UnameInfo {
    sysname: String,    // Operating system name (e.g., "Linux")
    nodename: String,   // Network node hostname (e.g., "server01")
    release: String,    // Kernel release (e.g., "5.4.0-109-generic")
    version: String,    // Kernel version details
    machine: String,    // Hardware architecture (e.g., "x86_64")
    processor: String,  // Processor type (e.g., "x86_64")
    hardware: String,   // Hardware platform (e.g., "x86_64")
    os: String,         // Operating system (e.g., "GNU/Linux")
    domain: String,     // Domain name (if any)
}

impl UnameInfo {
    /// Create a new UnameInfo with realistic values and a specific hostname
    pub fn new(hostname: &str) -> Self {
        // Generate a dynamic version string with build number and current date
        let now = Local::now();

        // Random kernel build number between 100 and 300
        let build_num = rng().random_range(100..300);

        // Dynamic kernel version with date/time
        let version_str = format!(
            "#{}-Ubuntu SMP {} {} {} {}:{}:{} UTC {}",
            build_num,
            match rng().random_range(0..3) {
                0 => "Mon",
                1 => "Wed",
                _ => "Fri"
            },
            match rng().random_range(0..3) {
                0 => "Mar",
                1 => "Apr",
                _ => "May"
            },
            rng().random_range(1..28),
            rng().random_range(8..18),
            rng().random_range(10..59),
            rng().random_range(10..59),
            now.year()
        );

        // Random kernel release
        let kernel_release = match rng().random_range(0..4) {
            0 => "5.4.0-109-generic",
            1 => "5.15.0-56-generic",
            2 => "6.2.0-26-generic",
            _ => "6.5.0-15-generic",
        }.to_string();

        UnameInfo {
            sysname: "Linux".to_string(),
            nodename: hostname.to_string(),
            release: kernel_release,
            version: version_str,
            machine: "x86_64".to_string(),
            processor: "x86_64".to_string(),
            hardware: "x86_64".to_string(),
            os: "GNU/Linux".to_string(),
            domain: "localdomain".to_string(),
        }
    }

    /// Generate complete uname output string as would be shown with -a flag
    fn full_string(&self) -> String {
        format!("{} {} {} {} {} {} {} {}",
                self.sysname, self.nodename, self.release, self.version,
                self.machine, self.processor, self.hardware, self.os)
    }
}

/// Handles the uname command with all its flags
pub fn handle_uname_command(cmd: &str, hostname: &str) -> String {
    let info = UnameInfo::new(hostname);

    // Handle "uname" with no args - just print system name
    if cmd == "uname" {
        return info.sysname.clone();
    }

    // Parse flags
    let parts: Vec<&str> = cmd.split_whitespace().collect();
    let mut show_all = false;
    let mut show_kernel_name = false;
    let mut show_node_name = false;
    let mut show_kernel_release = false;
    let mut show_kernel_version = false;
    let mut show_machine = false;
    let mut show_processor = false;
    let mut show_hardware = false;
    let mut show_os = false;
    let mut show_domain = false;
    let mut show_help = false;
    let mut show_version = false;

    // Process flags
    for part in &parts[1..] {
        match *part {
            "-a" | "--all" => show_all = true,
            "-s" | "--kernel-name" => show_kernel_name = true,
            "-n" | "--nodename" => show_node_name = true,
            "-r" | "--kernel-release" => show_kernel_release = true,
            "-v" | "--kernel-version" => show_kernel_version = true,
            "-m" | "--machine" => show_machine = true,
            "-p" | "--processor" => show_processor = true,
            "-i" | "--hardware-platform" => show_hardware = true,
            "-o" | "--operating-system" => show_os = true,
            "-d" | "--domain" => show_domain = true,
            "--help" => show_help = true,
            "--version" => show_version = true,
            // For combined short options like -snrvm
            _ if part.starts_with('-') && !part.starts_with("--") => {
                for c in part[1..].chars() {
                    match c {
                        'a' => show_all = true,
                        's' => show_kernel_name = true,
                        'n' => show_node_name = true,
                        'r' => show_kernel_release = true,
                        'v' => show_kernel_version = true,
                        'm' => show_machine = true,
                        'p' => show_processor = true,
                        'i' => show_hardware = true,
                        'o' => show_os = true,
                        'd' => show_domain = true,
                        _ => {} // Ignore unknown flags
                    }
                }
            },
            _ => {} // Ignore arguments that don't start with -
        }
    }

    // Handle help request
    if show_help {
        return concat!(
        "Usage: uname [OPTION]...\r\n",
        "Print certain system information. With no OPTION, same as -s.\r\n",
        "\r\n",
        "  -a, --all                print all information, in the following order:\r\n",
        "  -s, --kernel-name        print the kernel name\r\n",
        "  -n, --nodename           print the network node hostname\r\n",
        "  -r, --kernel-release     print the kernel release\r\n",
        "  -v, --kernel-version     print the kernel version\r\n",
        "  -m, --machine            print the machine hardware name\r\n",
        "  -p, --processor          print the processor type\r\n",
        "  -i, --hardware-platform  print the hardware platform\r\n",
        "  -o, --operating-system   print the operating system\r\n",
        "  -d, --domain             print the domain name\r\n",
        "      --help               display this help and exit\r\n",
        "      --version            output version information and exit\r\n"
        ).to_string();
    }

    // Handle version request
    if show_version {
        return concat!(
        "uname (GNU coreutils) 8.32\r\n",
        "Copyright (C) 2020 Free Software Foundation, Inc.\r\n",
        "License GPLv3+: GNU GPL version 3 or later <https://gnu.org/licenses/gpl.html>.\r\n",
        "This is free software: you are free to change and redistribute it.\r\n",
        "There is NO WARRANTY, to the extent permitted by law.\r\n",
        "\r\n",
        "Written by David MacKenzie.\r\n"
        ).to_string();
    }

    // If -a flag is present, it overrides all others
    if show_all {
        return info.full_string();
    }

    // If no flags are specified after parsing, default to -s
    if !(show_kernel_name || show_node_name || show_kernel_release ||
        show_kernel_version || show_machine || show_processor ||
        show_hardware || show_os || show_domain) {
        show_kernel_name = true;
    }

    // Build output based on selected flags
    let mut result = Vec::new();

    if show_kernel_name {
        result.push(info.sysname.clone());
    }

    if show_node_name {
        result.push(info.nodename.clone());
    }

    if show_kernel_release {
        result.push(info.release.clone());
    }

    if show_kernel_version {
        result.push(info.version.clone());
    }

    if show_machine {
        result.push(info.machine.clone());
    }

    if show_processor {
        result.push(info.processor.clone());
    }

    if show_hardware {
        result.push(info.hardware.clone());
    }

    if show_os {
        result.push(info.os.clone());
    }

    if show_domain {
        result.push(info.domain.clone());
    }

    result.join(" ")
}