use async_trait::async_trait;
use super::command_trait::{Command, CommandResult};
use super::context::CommandContext;
use chrono::{DateTime, Duration, Local};
use rand::{Rng, rng};

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
}

/// PS command implementation using the new trait system
pub struct PsCommand;

#[async_trait]
impl Command for PsCommand {
    fn name(&self) -> &'static str {
        "ps"
    }
    
    fn help(&self) -> String {
        "Usage: ps [options]\n\
        Display information about running processes.\n\
        \n\
        -e, -A, --everyone      show processes for all users\n\
        -f, --full              show full-format listing\n\
        -u, --user              show processes for specified users\n\
        -o, --format            specify output format\n\
        -p, --pid               show processes with specified PIDs\n\
        -t, --tty               show processes attached to specified terminals\n\
        -x, --no-tty            show processes not attached to a terminal\n\
        --help                  display this help and exit\n\
        --version               output version information and exit\n".to_string()
    }
    
    fn version(&self) -> String {
        "ps from procps-ng 3.3.15\n".to_string()
    }
    
    async fn execute(&self, args: &str, context: &mut CommandContext) -> CommandResult {
        // Handle help and version flags
        if args.contains("--help") {
            return Ok(self.help());
        }
        
        if args.contains("--version") {
            return Ok(self.version());
        }
        
        let processes = Self::generate_fake_processes(&context.username);
        let output = Self::format_process_list(&processes, args);
        Ok(output)
    }
}

impl PsCommand {
    fn generate_fake_processes(current_user: &str) -> Vec<Process> {
        let mut processes = Vec::new();
        let mut rng = rng();
        
        // System processes (common ones)
        let system_processes = vec![
            (1, "root", "[init]"),
            (2, "root", "[kthreadd]"),
            (3, "root", "[rcu_gp]"),
            (4, "root", "[rcu_par_gp]"),
            (6, "root", "[kworker/0:0H]"),
            (8, "root", "[mm_percpu_wq]"),
            (9, "root", "[ksoftirqd/0]"),
            (10, "root", "[migration/0]"),
            (11, "root", "[rcu_preempt]"),
            (12, "root", "[rcu_sched]"),
            (13, "root", "[rcu_bh]"),
            (14, "root", "[watchdog/0]"),
            (20, "root", "[kdevtmpfs]"),
            (21, "root", "[netns]"),
            (22, "root", "[kauditd]"),
            (25, "root", "[khungtaskd]"),
            (26, "root", "[oom_reaper]"),
            (27, "root", "[writeback]"),
            (28, "root", "[kcompactd0]"),
            (29, "root", "[ksmd]"),
            (30, "root", "[khugepaged]"),
            (120, "root", "/sbin/init"),
            (150, "root", "[kswapd0]"),
            (200, "systemd+", "/usr/lib/systemd/systemd-resolved"),
            (220, "root", "/usr/sbin/cron -f"),
            (240, "root", "/usr/sbin/sshd -D"),
            (300, "www-data", "/usr/sbin/apache2 -k start"),
            (350, "mysql", "/usr/sbin/mysqld"),
            (400, "root", "/usr/bin/docker-proxy"),
        ];
        
        for (pid, user, cmd) in system_processes {
            processes.push(Process::new(pid, user.to_string(), cmd.to_string()));
        }
        
        // User processes
        let user_processes = vec![
            format!("{}", rng.random_range(1000..2000)),
            format!("{}", rng.random_range(2000..3000)),
            format!("{}", rng.random_range(3000..4000)),
        ];
        
        for pid_str in user_processes {
            let pid: u32 = pid_str.parse().unwrap_or(1000);
            processes.push(Process::new(pid, current_user.to_string(), "/bin/bash".to_string()));
        }
        
        // Add current shell process
        processes.push(Process::new(
            rng.random_range(5000..6000),
            current_user.to_string(),
            "ps".to_string()
        ));
        
        processes.sort_by(|a, b| a.pid.cmp(&b.pid));
        processes
    }
    
    fn format_process_list(processes: &[Process], args: &str) -> String {
        let mut result = String::new();
        let show_all = args.contains("-e") || args.contains("-A") || args.contains("--everyone");
        let full_format = args.contains("-f") || args.contains("--full");
        
        if full_format {
            result.push_str(&format!("{:<8} {:>5} {:>5} {:>5} {:<5} {:<8} {:<5} {:<8} {}\r\n",
                                   "UID", "PID", "PPID", "C", "STIME", "TTY", "TIME", "CMD", ""));
        } else {
            result.push_str(&format!("{:>5} {:<8} {:<8} {}\r\n",
                                   "PID", "TTY", "TIME", "CMD"));
        }
        
        let filtered_processes: Vec<&Process> = if show_all {
            processes.iter().collect()
        } else {
            processes.iter().filter(|p| p.tty != "?").collect()
        };
        
        for process in filtered_processes {
            if full_format {
                result.push_str(&format!("{:<8} {:>5} {:>5} {:>5} {:<5} {:<8} {:<5} {:<8} {}\r\n",
                                       process.user,
                                       process.pid,
                                       if process.pid == 1 { 0 } else { 1 }, // Fake PPID
                                       (process.cpu_percent as u32).min(99),
                                       process.start_time.format("%H:%M"),
                                       process.tty,
                                       process.format_time(),
                                       process.command,
                                       ""));
            } else {
                result.push_str(&format!("{:>5} {:<8} {:<8} {}\r\n",
                                       process.pid,
                                       process.tty,
                                       process.format_time(),
                                       process.command));
            }
        }
        
        result
    }
}