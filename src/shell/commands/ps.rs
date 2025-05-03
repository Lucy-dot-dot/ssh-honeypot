use chrono::{DateTime, Duration, Local};
use rand::{Rng, rng};
use std::collections::HashMap;


/// Represents a simulated process
struct Process {
    pid: u32,
    user: String,
    command: String,
    cpu_percent: f32,
    mem_percent: f32,
    vsz: u32,
    rss: u32,
    tty: String,
    stat: String,
    start_time: DateTime<Local>,
    elapsed: Duration,
}

impl Process {
    fn new(pid: u32, user: String, command: String) -> Self {
        let mut rng = rng();
        let start_time = Local::now() - Duration::minutes(rng.random_range(0..1440)); // Random start within last day

        Process {
            pid,
            user,
            command,
            cpu_percent: rng.random_range(0.0..5.0),
            mem_percent: rng.random_range(0.0..2.0),
            vsz: rng.random_range(1000..300000),
            rss: rng.random_range(500..50000),
            tty: if pid < 300 || rng.random_bool(0.7) { "?".to_string() } else { format!("pts/{}", rng.random_range(0..4)) },
            stat: {
                let states = ["R", "S", "D", "Z", "T"];
                let flags = ["", "+", "<", "s", "l", "N"];
                format!("{}{}",
                        states[rng.random_range(0..states.len())],
                        flags[rng.random_range(0..flags.len())])
            },
            start_time,
            elapsed: Duration::minutes(rng.random_range(0..500)),
        }
    }

    fn format_time(&self) -> String {
        let minutes = self.elapsed.num_minutes();
        if minutes < 60 {
            format!("0:{:02}", minutes)
        } else {
            format!("{}:{:02}", minutes / 60, minutes % 60)
        }
    }

    fn format_start_time(&self) -> String {
        // If today, show time, otherwise show date
        let now = Local::now();
        if now.date_naive() == self.start_time.date_naive() {
            self.start_time.format("%H:%M").to_string()
        } else {
            self.start_time.format("%b%d").to_string()
        }
    }
}

/// Generates a list of common system processes
fn generate_system_processes() -> Vec<Process> {
    let common_processes = vec![
        (1, "root", "/sbin/init"),
        (2, "root", "[kthreadd]"),
        (10, "root", "[rcu_tasks_kthr]"),
        (11, "root", "[rcu_sched]"),
        (12, "root", "[migration/0]"),
        (16, "root", "[ksoftirqd/0]"),
        (17, "root", "[rcu_preempt]"),
        (18, "root", "[rcub/0]"),
        (20, "root", "[kworker/0:1H]"),
        (21, "root", "[kworker/u8:1]"),
        (89, "root", "/lib/systemd/systemd-journald"),
        (172, "systemd+", "/lib/systemd/systemd-resolved"),
        (208, "root", "/usr/sbin/cron -f"),
        (209, "root", "/usr/bin/dbus-daemon --system --address=systemd:"),
        (240, "root", "/usr/sbin/sshd -D"),
        (306, "root", "/sbin/agetty -o -p -- \\u --noclear tty1 linux"),
        (400, "mysql", "/usr/sbin/mysqld"),
        (455, "www-data", "/usr/sbin/apache2 -k start"),
        (457, "www-data", "/usr/sbin/apache2 -k start"),
        (458, "www-data", "/usr/sbin/apache2 -k start"),
        (500, "user", "/lib/systemd/systemd --user"),
        (520, "user", "bash"),
    ];

    common_processes.into_iter()
        .map(|(pid, user, command)| Process::new(pid, user.to_string(), command.to_string()))
        .collect()
}

/// Generate random user processes
fn generate_user_processes() -> Vec<Process> {
    let mut rng = rng();
    let user_commands = vec![
        "vim config.txt",
        "grep -r \"error\" /var/log",
        "tail -f /var/log/syslog",
        "node server.js",
        "python3 script.py",
        "java -jar app.jar",
        "cargo run",
        "npm start",
        "ssh user@remote",
        "/bin/bash",
        "[kworker/u8:0]",
    ];

    let count = rng.random_range(3..8);
    let mut processes = Vec::with_capacity(count);

    for _ in 0..count {
        let pid = rng.random_range(1000..9999);
        let user = if rng.random_bool(0.8) { "user" } else { "root" };
        let command = user_commands[rng.random_range(0..user_commands.len())];
        processes.push(Process::new(pid, user.to_string(), command.to_string()));
    }

    processes
}

/// Handle the ps command with various flags
pub fn handle_ps_command(cmd: &str) -> String {
    let mut processes = generate_system_processes();
    processes.extend(generate_user_processes());

    // Add the ps command itself as the last process
    let ps_pid = rng().random_range(1000..9999);
    processes.push(Process::new(ps_pid, "user".to_string(), cmd.to_string()));

    // Sort by PID
    processes.sort_by_key(|p| p.pid);

    // Parse flags
    let cmd = cmd.trim();
    let parts: Vec<&str> = cmd.split_whitespace().collect();

    // Default output format (no args or just "ps")
    if parts.len() <= 1 {
        return format_simple_ps(&processes);
    }

    // Handle common flags
    let mut show_all = false;
    let mut long_format = false;
    let mut show_forest = false;
    let mut show_header = true;
    let mut wide_output = false;

    for part in &parts[1..] {
        match *part {
            "a" | "-a" => show_all = true,
            "u" | "-u" => long_format = true,
            "x" | "-x" => wide_output = true,
            "f" | "-f" => show_forest = true,
            "-e" | "-A" => show_all = true,
            "aux" | "-aux" => {
                show_all = true;
                long_format = true;
                wide_output = true;
            },
            "--no-headers" => show_header = false,
            _ => {}
        }
    }

    // Generate output based on flags
    if long_format {
        format_long_ps(&processes, show_all, show_header)
    } else if show_forest {
        format_forest_ps(&processes, show_all, show_header)
    } else {
        format_simple_ps(&processes)
    }
}

/// Format PS output in simple format
fn format_simple_ps(processes: &[Process]) -> String {
    let mut result = String::from("  PID TTY          TIME CMD\r\n");

    for proc in processes.iter().filter(|p| p.tty != "?") {
        result.push_str(&format!(
            "{:5} {:4}       {:5} {}\r\n",
            proc.pid,
            proc.tty,
            proc.format_time(),
            proc.command,
        ));
    }

    result
}

/// Format PS output in long format (ps aux)
fn format_long_ps(processes: &[Process], show_all: bool, show_header: bool) -> String {
    let mut result = String::new();

    if show_header {
        result.push_str("USER       PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND\r\n");
    }

    for proc in processes.iter().filter(|p| show_all || p.tty != "?") {
        result.push_str(&format!(
            "{:8} {:5} {:4.1} {:4.1} {:6} {:5} {:8} {:4} {:5}   {:5} {}\r\n",
            proc.user,
            proc.pid,
            proc.cpu_percent,
            proc.mem_percent,
            proc.vsz,
            proc.rss,
            proc.tty,
            proc.stat,
            proc.format_start_time(),
            proc.format_time(),
            proc.command,
        ));
    }

    result
}

/// Format PS output in forest format (ps f)
fn format_forest_ps(processes: &[Process], show_all: bool, show_header: bool) -> String {
    // Build parent-child relationships
    let mut child_map: HashMap<u32, Vec<u32>> = HashMap::new();

    for proc in processes {
        if proc.pid > 1 {
            // Simplistic approach: assume processes with lower PIDs are parents
            let potential_parent = proc.pid / 10;
            if potential_parent >= 1 {
                child_map.entry(potential_parent).or_default().push(proc.pid);
            }
        }
    }

    let mut result = String::new();

    if show_header {
        result.push_str("  PID TTY      STAT   TIME COMMAND\r\n");
    }

    // Generate forest output recursively starting from PID 1
    fn add_process_tree(
        pid: u32,
        depth: usize,
        processes: &[Process],
        child_map: &HashMap<u32, Vec<u32>>,
        show_all: bool,
        result: &mut String
    ) {
        if let Some(proc) = processes.iter().find(|p| p.pid == pid) {
            if show_all || proc.tty != "?" {
                let prefix = "| ".repeat(depth);
                result.push_str(&format!(
                    "{:5} {:8} {:4} {:5} {}{}{}",
                    proc.pid,
                    proc.tty,
                    proc.stat,
                    proc.format_time(),
                    prefix,
                    if depth > 0 { "\\_ " } else { "" },
                    proc.command,
                ));
                result.push_str("\r\n");
            }

            // Add all children
            if let Some(children) = child_map.get(&pid) {
                for &child_pid in children {
                    add_process_tree(child_pid, depth + 1, processes, child_map, show_all, result);
                }
            }
        }
    }

    add_process_tree(1, 0, processes, &child_map, show_all, &mut result);

    result
}