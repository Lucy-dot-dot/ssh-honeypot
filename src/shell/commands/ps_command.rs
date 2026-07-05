use super::command_trait::{Command, CommandResult};
use super::context::CommandContext;
use async_trait::async_trait;
use chrono::{DateTime, Duration, Local};
use rand::{RngExt, rng};

/// Categorizes a simulated process so its randomized resource usage looks realistic.
#[derive(Clone, Copy)]
enum ProcessType {
    /// Kernel thread, shown in brackets (e.g. `[kthreadd]`). Essentially zero resources.
    KernelThread,
    /// Core systemd / early-boot daemon (journald, udevd, logind, ...). Small, stable usage.
    SystemdDaemon,
    /// Long-running service daemon (apache, mysqld, dockerd, ...). Larger memory footprint.
    ServiceDaemon,
    /// Interactive user process (bash, ps, ...). On a TTY, recent start time.
    UserProcess,
}

/// Represents a simulated process
#[allow(dead_code)]
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
    /// Builds a process with resource usage randomized to fit its category.
    /// `boot_time` is shared by all system processes so their STIME is consistent.
    fn new(
        pid: u32,
        user: String,
        command: String,
        ptype: ProcessType,
        boot_time: DateTime<Local>,
    ) -> Self {
        let mut rng = rng();
        let mut p = Process {
            pid,
            user,
            command,
            cpu_percent: 0.0,
            mem_percent: 0.0,
            vsz: 0,
            rss: 0,
            tty: "?".to_string(),
            stat: "S".to_string(),
            start_time: boot_time,
            elapsed: Duration::zero(),
        };

        match ptype {
            ProcessType::KernelThread => {
                // Kernel threads use essentially no CPU/memory.
                p.cpu_percent = rng.random_range(0.0..0.1);
                p.mem_percent = 0.0;
                p.vsz = 0;
                p.rss = 0;
                p.tty = "?".to_string();
                p.stat = "S".to_string();
                p.start_time = boot_time;
                p.elapsed = Duration::seconds(rng.random_range(0..50));
            }
            ProcessType::SystemdDaemon => {
                p.cpu_percent = rng.random_range(0.0..0.3);
                p.mem_percent = rng.random_range(0.1..1.0);
                p.vsz = rng.random_range(40000..180000);
                p.rss = rng.random_range(3000..25000);
                p.tty = "?".to_string();
                p.stat = "Ss".to_string();
                p.start_time = boot_time;
                p.elapsed = Duration::seconds(rng.random_range(0..180));
            }
            ProcessType::ServiceDaemon => {
                p.cpu_percent = rng.random_range(0.0..2.0);
                p.mem_percent = rng.random_range(0.3..5.0);
                p.vsz = rng.random_range(100000..1_200_000);
                p.rss = rng.random_range(8000..150_000);
                p.tty = "?".to_string();
                let states = ["Ss", "Sl", "S"];
                p.stat = states[rng.random_range(0..states.len())].to_string();
                p.start_time = boot_time;
                p.elapsed = Duration::seconds(rng.random_range(0..600));
            }
            ProcessType::UserProcess => {
                p.cpu_percent = rng.random_range(0.0..5.0);
                p.mem_percent = rng.random_range(0.0..2.0);
                p.vsz = rng.random_range(1000..300000);
                p.rss = rng.random_range(500..50000);
                p.tty = format!("pts/{}", rng.random_range(0..4));
                let states = ["R", "S", "D", "Z", "T"];
                let flags = ["", "+", "<", "s", "l", "N"];
                p.stat = format!(
                    "{}{}",
                    states[rng.random_range(0..states.len())],
                    flags[rng.random_range(0..flags.len())]
                );
                p.start_time = Local::now() - Duration::minutes(rng.random_range(0..120));
                p.elapsed = Duration::minutes(rng.random_range(0..500));
            }
        }

        p
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
        --version               output version information and exit\n"
            .to_string()
    }

    fn version(&self) -> String {
        "ps from procps-ng 3.3.15\n".to_string()
    }

    async fn execute(&self, args: &[String], context: &mut CommandContext) -> CommandResult {
        // Handle help and version flags
        if args.iter().any(|a| a == "--help") {
            return Ok(self.help());
        }

        if args.iter().any(|a| a == "--version") {
            return Ok(self.version());
        }

        let processes = Self::generate_fake_processes(&context.username);
        let output = Self::format_process_list(&processes, args);
        Ok(output)
    }
}

impl PsCommand {
    fn generate_fake_processes(current_user: &str) -> Vec<Process> {
        let mut rng = rng();

        // Single shared boot time so every system process reports the same STIME.
        // Pretends the machine has been up between ~8h and ~23h.
        let boot_time = Local::now() - Duration::minutes(rng.random_range(480..1400));

        // Static template: (pid, user, command, process_type).
        let system_processes: &[(u32, &str, &str, ProcessType)] = &[
            // --- PID 1: the init system ---
            (1, "root", "/sbin/init splash", ProcessType::SystemdDaemon),
            // --- Kernel threads (spawned by kthreadd, PIDs 2..~200) ---
            (2, "root", "[kthreadd]", ProcessType::KernelThread),
            (3, "root", "[rcu_gp]", ProcessType::KernelThread),
            (4, "root", "[rcu_par_gp]", ProcessType::KernelThread),
            (
                6,
                "root",
                "[kworker/0:0H-kblockd]",
                ProcessType::KernelThread,
            ),
            (8, "root", "[mm_percpu_wq]", ProcessType::KernelThread),
            (9, "root", "[ksoftirqd/0]", ProcessType::KernelThread),
            (10, "root", "[rcu_tasks_rude_]", ProcessType::KernelThread),
            (11, "root", "[rcu_tasks_trace]", ProcessType::KernelThread),
            (12, "root", "[cpuhp/0]", ProcessType::KernelThread),
            (13, "root", "[idle_inject/0]", ProcessType::KernelThread),
            (14, "root", "[migration/0]", ProcessType::KernelThread),
            (15, "root", "[cpuhp/1]", ProcessType::KernelThread),
            (16, "root", "[idle_inject/1]", ProcessType::KernelThread),
            (17, "root", "[migration/1]", ProcessType::KernelThread),
            (18, "root", "[ksoftirqd/1]", ProcessType::KernelThread),
            (
                20,
                "root",
                "[kworker/1:0H-kblockd]",
                ProcessType::KernelThread,
            ),
            (22, "root", "[kdevtmpfs]", ProcessType::KernelThread),
            (23, "root", "[netns]", ProcessType::KernelThread),
            (24, "root", "[rcu_tasks_kthre]", ProcessType::KernelThread),
            (25, "root", "[kauditd]", ProcessType::KernelThread),
            (26, "root", "[khungtaskd]", ProcessType::KernelThread),
            (27, "root", "[oom_reaper]", ProcessType::KernelThread),
            (28, "root", "[writeback]", ProcessType::KernelThread),
            (29, "root", "[kcompactd0]", ProcessType::KernelThread),
            (30, "root", "[ksmd]", ProcessType::KernelThread),
            (31, "root", "[khugepaged]", ProcessType::KernelThread),
            (33, "root", "[kintegrityd]", ProcessType::KernelThread),
            (34, "root", "[kblockd]", ProcessType::KernelThread),
            (35, "root", "[blkcg_punt_bio]", ProcessType::KernelThread),
            (40, "root", "[tpm_dev_wq]", ProcessType::KernelThread),
            (41, "root", "[ata_sff]", ProcessType::KernelThread),
            (43, "root", "[md]", ProcessType::KernelThread),
            (44, "root", "[edac-poller]", ProcessType::KernelThread),
            (45, "root", "[devfreq_wq]", ProcessType::KernelThread),
            (46, "root", "[watchdogd]", ProcessType::KernelThread),
            (48, "root", "[kworker/0:1]", ProcessType::KernelThread),
            (49, "root", "[kworker/1:1]", ProcessType::KernelThread),
            (50, "root", "[kswapd0]", ProcessType::KernelThread),
            (51, "root", "[ecryptfs-kthrea]", ProcessType::KernelThread),
            (52, "root", "[kworker/u32:0]", ProcessType::KernelThread),
            (53, "root", "[kworker/u32:1]", ProcessType::KernelThread),
            (54, "root", "[kworker/u32:2]", ProcessType::KernelThread),
            (60, "root", "[cryptd]", ProcessType::KernelThread),
            (61, "root", "[kstrp]", ProcessType::KernelThread),
            (62, "root", "[charger_manager]", ProcessType::KernelThread),
            (150, "root", "[kworker/0:1H]", ProcessType::KernelThread),
            (151, "root", "[kworker/1:1H]", ProcessType::KernelThread),
            (152, "root", "[kworker/0:2]", ProcessType::KernelThread),
            (153, "root", "[kworker/1:2]", ProcessType::KernelThread),
            (154, "root", "[kworker/u32:3]", ProcessType::KernelThread),
            (190, "root", "[jbd2/sda1-8]", ProcessType::KernelThread),
            (191, "root", "[ext4-rsv-conver]", ProcessType::KernelThread),
            (192, "root", "[ipv6_addrconf]", ProcessType::KernelThread),
            // --- Core systemd / early-boot daemons ---
            (
                260,
                "root",
                "/lib/systemd/systemd-journald",
                ProcessType::SystemdDaemon,
            ),
            (
                275,
                "root",
                "/lib/systemd/systemd-udevd",
                ProcessType::SystemdDaemon,
            ),
            (
                285,
                "systemd+",
                "/lib/systemd/systemd-resolved",
                ProcessType::SystemdDaemon,
            ),
            (
                290,
                "systemd+",
                "/lib/systemd/systemd-networkd",
                ProcessType::SystemdDaemon,
            ),
            (
                300,
                "systemd+",
                "/lib/systemd/systemd-timesyncd",
                ProcessType::SystemdDaemon,
            ),
            (305, "root", "/usr/sbin/cron -f", ProcessType::SystemdDaemon),
            (
                310,
                "message+",
                "/usr/bin/dbus-daemon --system --address=systemd --nofork --nopidfile",
                ProcessType::SystemdDaemon,
            ),
            (
                315,
                "root",
                "/lib/systemd/systemd-logind",
                ProcessType::SystemdDaemon,
            ),
            (
                320,
                "syslog",
                "/usr/sbin/rsyslogd -n -iNONE",
                ProcessType::SystemdDaemon,
            ),
            (
                325,
                "root",
                "/usr/sbin/irqbalance --foreground",
                ProcessType::SystemdDaemon,
            ),
            (
                330,
                "root",
                "/usr/lib/accountsservice/accounts-daemon",
                ProcessType::SystemdDaemon,
            ),
            (
                335,
                "root",
                "/usr/sbin/NetworkManager --no-daemon",
                ProcessType::SystemdDaemon,
            ),
            (
                340,
                "root",
                "/usr/lib/policykit-1/polkitd --no-debug",
                ProcessType::SystemdDaemon,
            ),
            (
                345,
                "root",
                "/usr/sbin/thermald --systemd",
                ProcessType::SystemdDaemon,
            ),
            (
                350,
                "root",
                "/usr/lib/snapd/snapd",
                ProcessType::SystemdDaemon,
            ),
            (355, "root", "/usr/sbin/sshd -D", ProcessType::SystemdDaemon),
            (360, "root", "/usr/sbin/atd -f", ProcessType::SystemdDaemon),
            (
                365,
                "root",
                "/lib/systemd/systemd-machined",
                ProcessType::SystemdDaemon,
            ),
            (
                370,
                "root",
                "/sbin/multipathd -d -s",
                ProcessType::SystemdDaemon,
            ),
            (
                375,
                "root",
                "/usr/libexec/fwupd/fwupd",
                ProcessType::SystemdDaemon,
            ),
            (
                380,
                "root",
                "/usr/sbin/ModemManager",
                ProcessType::SystemdDaemon,
            ),
            (
                385,
                "root",
                "/lib/systemd/systemd-networkd-wait-online",
                ProcessType::SystemdDaemon,
            ),
            // --- Long-running service daemons ---
            (
                500,
                "root",
                "/usr/sbin/apache2 -k start",
                ProcessType::ServiceDaemon,
            ),
            (
                501,
                "www-data",
                "/usr/sbin/apache2 -k start",
                ProcessType::ServiceDaemon,
            ),
            (
                502,
                "www-data",
                "/usr/sbin/apache2 -k start",
                ProcessType::ServiceDaemon,
            ),
            (
                503,
                "www-data",
                "/usr/sbin/apache2 -k start",
                ProcessType::ServiceDaemon,
            ),
            (
                504,
                "www-data",
                "/usr/sbin/apache2 -k start",
                ProcessType::ServiceDaemon,
            ),
            (
                505,
                "www-data",
                "/usr/sbin/apache2 -k start",
                ProcessType::ServiceDaemon,
            ),
            (510, "mysql", "/usr/sbin/mysqld", ProcessType::ServiceDaemon),
            (
                520,
                "redis",
                "redis-server 127.0.0.1:6379",
                ProcessType::ServiceDaemon,
            ),
            (
                530,
                "root",
                "/usr/bin/containerd",
                ProcessType::ServiceDaemon,
            ),
            (
                531,
                "root",
                "/usr/bin/dockerd -H fd:// --containerd=/run/containerd/containerd.sock",
                ProcessType::ServiceDaemon,
            ),
            (
                540,
                "root",
                "/usr/bin/docker-proxy -proto tcp -host-ip 0.0.0.0 -host-port 8080",
                ProcessType::ServiceDaemon,
            ),
            (
                541,
                "root",
                "/usr/bin/docker-proxy -proto tcp -host-ip 0.0.0.0 -host-port 3306",
                ProcessType::ServiceDaemon,
            ),
            (
                550,
                "postgres",
                "/usr/lib/postgresql/14/bin/postgres -D /var/lib/postgresql/14/main -c config_file=/etc/postgresql/14/main/postgresql.conf",
                ProcessType::ServiceDaemon,
            ),
        ];

        let mut processes: Vec<Process> = system_processes
            .iter()
            .map(|(pid, user, cmd, ptype)| {
                Process::new(*pid, user.to_string(), cmd.to_string(), *ptype, boot_time)
            })
            .collect();

        // A few interactive user shell sessions on PTYs.
        for _ in 0..3 {
            let pid = rng.random_range(1000..4000);
            processes.push(Process::new(
                pid,
                current_user.to_string(),
                "/bin/bash".to_string(),
                ProcessType::UserProcess,
                boot_time,
            ));
        }

        // The ps invocation itself (runs in the current session).
        processes.push(Process::new(
            rng.random_range(5000..6000),
            current_user.to_string(),
            "ps".to_string(),
            ProcessType::UserProcess,
            boot_time,
        ));

        processes.sort_by_key(|p| p.pid);
        processes
    }

    fn format_process_list(processes: &[Process], args: &[String]) -> String {
        let mut result = String::new();
        let show_all = args
            .iter()
            .any(|a| a == "-e" || a == "-A" || a == "--everyone");
        let full_format = args.iter().any(|a| a == "-f" || a == "--full");

        if full_format {
            result.push_str(&format!(
                "{:<8} {:>5} {:>5} {:>5} {:<5} {:<8} {:<5} {:<8} {}\r\n",
                "UID", "PID", "PPID", "C", "STIME", "TTY", "TIME", "CMD", ""
            ));
        } else {
            result.push_str(&format!(
                "{:>5} {:<8} {:<8} {}\r\n",
                "PID", "TTY", "TIME", "CMD"
            ));
        }

        let filtered_processes: Vec<&Process> = if show_all {
            processes.iter().collect()
        } else {
            processes.iter().filter(|p| p.tty != "?").collect()
        };

        for process in filtered_processes {
            if full_format {
                result.push_str(&format!(
                    "{:<8} {:>5} {:>5} {:>5} {:<5} {:<8} {:<5} {:<8} {}\r\n",
                    process.user,
                    process.pid,
                    if process.pid == 1 { 0 } else { 1 }, // Fake PPID
                    (process.cpu_percent as u32).min(99),
                    process.start_time.format("%H:%M"),
                    process.tty,
                    process.format_time(),
                    process.command,
                    ""
                ));
            } else {
                result.push_str(&format!(
                    "{:>5} {:<8} {:<8} {}\r\n",
                    process.pid,
                    process.tty,
                    process.format_time(),
                    process.command
                ));
            }
        }

        result
    }
}
