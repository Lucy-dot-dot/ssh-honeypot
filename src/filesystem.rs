use chrono::{DateTime, Local, TimeZone, Utc};
use std::collections::HashMap;
use std::sync::OnceLock;

// A struct to represent file metadata
pub struct FakeFile {
    pub name: String,
    pub is_dir: bool,
    pub size: u64,
    pub permissions: String,
    pub owner: String,
    pub group: String,
    pub modified: DateTime<Utc>,
}

// A struct to represent a directory with its contents
pub struct FakeDir {
    pub path: String,
    pub files: Vec<FakeFile>,
}

static FILESYSTEM: OnceLock<HashMap<String, FakeDir>> = OnceLock::new();

// Initialize the fake filesystem with common directories and files
pub fn initialize_filesystem() -> HashMap<String, FakeDir> {
    let mut filesystem = HashMap::new();

    // Root directory
    filesystem.insert("/".to_string(), FakeDir {
        path: "/".to_string(),
        files: vec![
            FakeFile {
                name: "bin".to_string(),
                is_dir: true,
                size: 4096,
                permissions: "drwxr-xr-x".to_string(),
                owner: "root".to_string(),
                group: "root".to_string(),
                modified: Local.with_ymd_and_hms(2023, 12, 15, 10, 30, 0).unwrap().into(),
            },
            FakeFile {
                name: "boot".to_string(),
                is_dir: true,
                size: 4096,
                permissions: "drwxr-xr-x".to_string(),
                owner: "root".to_string(),
                group: "root".to_string(),
                modified: Local.with_ymd_and_hms(2023, 12, 15, 10, 30, 0).unwrap().into(),
            },
            FakeFile {
                name: "dev".to_string(),
                is_dir: true,
                size: 4096,
                permissions: "drwxr-xr-x".to_string(),
                owner: "root".to_string(),
                group: "root".to_string(),
                modified: Local.with_ymd_and_hms(2024, 3, 20, 8, 0, 0).unwrap().into(),
            },
            FakeFile {
                name: "etc".to_string(),
                is_dir: true,
                size: 4096,
                permissions: "drwxr-xr-x".to_string(),
                owner: "root".to_string(),
                group: "root".to_string(),
                modified: Local.with_ymd_and_hms(2024, 3, 20, 9, 15, 0).unwrap().into(),
            },
            FakeFile {
                name: "home".to_string(),
                is_dir: true,
                size: 4096,
                permissions: "drwxr-xr-x".to_string(),
                owner: "root".to_string(),
                group: "root".to_string(),
                modified: Local.with_ymd_and_hms(2023, 12, 15, 10, 30, 0).unwrap().into(),
            },
            FakeFile {
                name: "lib".to_string(),
                is_dir: true,
                size: 4096,
                permissions: "drwxr-xr-x".to_string(),
                owner: "root".to_string(),
                group: "root".to_string(),
                modified: Local.with_ymd_and_hms(2023, 12, 15, 10, 30, 0).unwrap().into(),
            },
            FakeFile {
                name: "lib64".to_string(),
                is_dir: true,
                size: 4096,
                permissions: "drwxr-xr-x".to_string(),
                owner: "root".to_string(),
                group: "root".to_string(),
                modified: Local.with_ymd_and_hms(2023, 12, 15, 10, 30, 0).unwrap().into(),
            },
            FakeFile {
                name: "media".to_string(),
                is_dir: true,
                size: 4096,
                permissions: "drwxr-xr-x".to_string(),
                owner: "root".to_string(),
                group: "root".to_string(),
                modified: Local.with_ymd_and_hms(2023, 12, 15, 10, 30, 0).unwrap().into(),
            },
            FakeFile {
                name: "mnt".to_string(),
                is_dir: true,
                size: 4096,
                permissions: "drwxr-xr-x".to_string(),
                owner: "root".to_string(),
                group: "root".to_string(),
                modified: Local.with_ymd_and_hms(2023, 12, 15, 10, 30, 0).unwrap().into(),
            },
            FakeFile {
                name: "opt".to_string(),
                is_dir: true,
                size: 4096,
                permissions: "drwxr-xr-x".to_string(),
                owner: "root".to_string(),
                group: "root".to_string(),
                modified: Local.with_ymd_and_hms(2023, 12, 15, 10, 30, 0).unwrap().into(),
            },
            FakeFile {
                name: "proc".to_string(),
                is_dir: true,
                size: 0,
                permissions: "dr-xr-xr-x".to_string(),
                owner: "root".to_string(),
                group: "root".to_string(),
                modified: Local::now().into(),
            },
            FakeFile {
                name: "root".to_string(),
                is_dir: true,
                size: 4096,
                permissions: "drwx------".to_string(),
                owner: "root".to_string(),
                group: "root".to_string(),
                modified: Local.with_ymd_and_hms(2024, 3, 10, 15, 45, 0).unwrap().into(),
            },
            FakeFile {
                name: "run".to_string(),
                is_dir: true,
                size: 4096,
                permissions: "drwxr-xr-x".to_string(),
                owner: "root".to_string(),
                group: "root".to_string(),
                modified: Local::now().into(),
            },
            FakeFile {
                name: "srv".to_string(),
                is_dir: true,
                size: 4096,
                permissions: "drwxr-xr-x".to_string(),
                owner: "root".to_string(),
                group: "root".to_string(),
                modified: Local.with_ymd_and_hms(2023, 12, 15, 10, 30, 0).unwrap().into(),
            },
            FakeFile {
                name: "sys".to_string(),
                is_dir: true,
                size: 0,
                permissions: "dr-xr-xr-x".to_string(),
                owner: "root".to_string(),
                group: "root".to_string(),
                modified: Local::now().into(),
            },
            FakeFile {
                name: "tmp".to_string(),
                is_dir: true,
                size: 4096,
                permissions: "drwxrwxrwt".to_string(),
                owner: "root".to_string(),
                group: "root".to_string(),
                modified: Local::now().into(),
            },
            FakeFile {
                name: "usr".to_string(),
                is_dir: true,
                size: 4096,
                permissions: "drwxr-xr-x".to_string(),
                owner: "root".to_string(),
                group: "root".to_string(),
                modified: Local.with_ymd_and_hms(2023, 12, 15, 10, 30, 0).unwrap().into(),
            },
            FakeFile {
                name: "var".to_string(),
                is_dir: true,
                size: 4096,
                permissions: "drwxr-xr-x".to_string(),
                owner: "root".to_string(),
                group: "root".to_string(),
                modified: Local.with_ymd_and_hms(2024, 3, 21, 8, 0, 0).unwrap().into(),
            },
        ],
    });

    // /home directory
    filesystem.insert("/home".to_string(), FakeDir {
        path: "/home".to_string(),
        files: vec![
            FakeFile {
                name: ".".to_string(),
                is_dir: true,
                size: 4096,
                permissions: "drwxr-xr-x".to_string(),
                owner: "root".to_string(),
                group: "root".to_string(),
                modified: Local.with_ymd_and_hms(2023, 12, 15, 10, 30, 0).unwrap().into(),
            },
            FakeFile {
                name: "..".to_string(),
                is_dir: true,
                size: 4096,
                permissions: "drwxr-xr-x".to_string(),
                owner: "root".to_string(),
                group: "root".to_string(),
                modified: Local.with_ymd_and_hms(2023, 12, 15, 10, 30, 0).unwrap().into(),
            },
            FakeFile {
                name: "user".to_string(),
                is_dir: true,
                size: 4096,
                permissions: "drwxr-xr-x".to_string(),
                owner: "user".to_string(),
                group: "user".to_string(),
                modified: Local.with_ymd_and_hms(2024, 3, 21, 9, 30, 0).unwrap().into(),
            },
            FakeFile {
                name: "admin".to_string(),
                is_dir: true,
                size: 4096,
                permissions: "drwxr-xr-x".to_string(),
                owner: "admin".to_string(),
                group: "admin".to_string(),
                modified: Local.with_ymd_and_hms(2024, 3, 15, 14, 20, 0).unwrap().into(),
            },
        ],
    });

    // /home/user directory
    filesystem.insert("/home/user".to_string(), FakeDir {
        path: "/home/user".to_string(),
        files: vec![
            FakeFile {
                name: ".".to_string(),
                is_dir: true,
                size: 4096,
                permissions: "drwxr-xr-x".to_string(),
                owner: "user".to_string(),
                group: "user".to_string(),
                modified: Local.with_ymd_and_hms(2024, 3, 21, 9, 30, 0).unwrap().into(),
            },
            FakeFile {
                name: "..".to_string(),
                is_dir: true,
                size: 4096,
                permissions: "drwxr-xr-x".to_string(),
                owner: "root".to_string(),
                group: "root".to_string(),
                modified: Local.with_ymd_and_hms(2023, 12, 15, 10, 30, 0).unwrap().into(),
            },
            FakeFile {
                name: ".bash_history".to_string(),
                is_dir: false,
                size: 1024,
                permissions: "-rw-------".to_string(),
                owner: "user".to_string(),
                group: "user".to_string(),
                modified: Local.with_ymd_and_hms(2024, 3, 21, 14, 30, 0).unwrap().into(),
            },
            FakeFile {
                name: ".bash_logout".to_string(),
                is_dir: false,
                size: 220,
                permissions: "-rw-r--r--".to_string(),
                owner: "user".to_string(),
                group: "user".to_string(),
                modified: Local.with_ymd_and_hms(2020, 2, 25, 12, 0, 0).unwrap().into(),
            },
            FakeFile {
                name: ".bashrc".to_string(),
                is_dir: false,
                size: 3771,
                permissions: "-rw-r--r--".to_string(),
                owner: "user".to_string(),
                group: "user".to_string(),
                modified: Local.with_ymd_and_hms(2020, 2, 25, 12, 0, 0).unwrap().into(),
            },
            FakeFile {
                name: ".profile".to_string(),
                is_dir: false,
                size: 807,
                permissions: "-rw-r--r--".to_string(),
                owner: "user".to_string(),
                group: "user".to_string(),
                modified: Local.with_ymd_and_hms(2020, 2, 25, 12, 0, 0).unwrap().into(),
            },
            FakeFile {
                name: ".ssh".to_string(),
                is_dir: true,
                size: 4096,
                permissions: "drwx------".to_string(),
                owner: "user".to_string(),
                group: "user".to_string(),
                modified: Local.with_ymd_and_hms(2024, 3, 10, 10, 0, 0).unwrap().into(),
            },
            FakeFile {
                name: "Documents".to_string(),
                is_dir: true,
                size: 4096,
                permissions: "drwxr-xr-x".to_string(),
                owner: "user".to_string(),
                group: "user".to_string(),
                modified: Local.with_ymd_and_hms(2024, 3, 18, 9, 0, 0).unwrap().into(),
            },
            FakeFile {
                name: "Downloads".to_string(),
                is_dir: true,
                size: 4096,
                permissions: "drwxr-xr-x".to_string(),
                owner: "user".to_string(),
                group: "user".to_string(),
                modified: Local.with_ymd_and_hms(2024, 3, 19, 14, 30, 0).unwrap().into(),
            },
            FakeFile {
                name: "notes.txt".to_string(),
                is_dir: false,
                size: 340,
                permissions: "-rw-r--r--".to_string(),
                owner: "user".to_string(),
                group: "user".to_string(),
                modified: Local.with_ymd_and_hms(2024, 3, 20, 11, 45, 0).unwrap().into(),
            },
            FakeFile {
                name: "backup.tar.gz".to_string(),
                is_dir: false,
                size: 5242880,
                permissions: "-rw-r--r--".to_string(),
                owner: "user".to_string(),
                group: "user".to_string(),
                modified: Local.with_ymd_and_hms(2024, 3, 15, 8, 30, 0).unwrap().into(),
            },
        ],
    });

    // /home/user/.ssh directory
    filesystem.insert("/home/user/.ssh".to_string(), FakeDir {
        path: "/home/user/.ssh".to_string(),
        files: vec![
            FakeFile {
                name: ".".to_string(),
                is_dir: true,
                size: 4096,
                permissions: "drwx------".to_string(),
                owner: "user".to_string(),
                group: "user".to_string(),
                modified: Local.with_ymd_and_hms(2024, 3, 10, 10, 0, 0).unwrap().into(),
            },
            FakeFile {
                name: "..".to_string(),
                is_dir: true,
                size: 4096,
                permissions: "drwxr-xr-x".to_string(),
                owner: "user".to_string(),
                group: "user".to_string(),
                modified: Local.with_ymd_and_hms(2024, 3, 21, 9, 30, 0).unwrap().into(),
            },
            FakeFile {
                name: "authorized_keys".to_string(),
                is_dir: false,
                size: 420,
                permissions: "-rw-------".to_string(),
                owner: "user".to_string(),
                group: "user".to_string(),
                modified: Local.with_ymd_and_hms(2024, 3, 10, 10, 0, 0).unwrap().into(),
            },
            FakeFile {
                name: "id_rsa".to_string(),
                is_dir: false,
                size: 2602,
                permissions: "-rw-------".to_string(),
                owner: "user".to_string(),
                group: "user".to_string(),
                modified: Local.with_ymd_and_hms(2024, 3, 10, 10, 0, 0).unwrap().into(),
            },
            FakeFile {
                name: "id_rsa.pub".to_string(),
                is_dir: false,
                size: 420,
                permissions: "-rw-r--r--".to_string(),
                owner: "user".to_string(),
                group: "user".to_string(),
                modified: Local.with_ymd_and_hms(2024, 3, 10, 10, 0, 0).unwrap().into(),
            },
            FakeFile {
                name: "known_hosts".to_string(),
                is_dir: false,
                size: 1320,
                permissions: "-rw-r--r--".to_string(),
                owner: "user".to_string(),
                group: "user".to_string(),
                modified: Local.with_ymd_and_hms(2024, 3, 10, 10, 0, 0).unwrap().into(),
            },
        ],
    });

    // /var directory
    filesystem.insert("/var".to_string(), FakeDir {
        path: "/var".to_string(),
        files: vec![
            FakeFile {
                name: ".".to_string(),
                is_dir: true,
                size: 4096,
                permissions: "drwxr-xr-x".to_string(),
                owner: "root".to_string(),
                group: "root".to_string(),
                modified: Local.with_ymd_and_hms(2024, 3, 21, 8, 0, 0).unwrap().into(),
            },
            FakeFile {
                name: "..".to_string(),
                is_dir: true,
                size: 4096,
                permissions: "drwxr-xr-x".to_string(),
                owner: "root".to_string(),
                group: "root".to_string(),
                modified: Local.with_ymd_and_hms(2023, 12, 15, 10, 30, 0).unwrap().into(),
            },
            FakeFile {
                name: "backups".to_string(),
                is_dir: true,
                size: 4096,
                permissions: "drwxr-xr-x".to_string(),
                owner: "root".to_string(),
                group: "root".to_string(),
                modified: Local.with_ymd_and_hms(2024, 3, 15, 3, 0, 0).unwrap().into(),
            },
            FakeFile {
                name: "cache".to_string(),
                is_dir: true,
                size: 4096,
                permissions: "drwxr-xr-x".to_string(),
                owner: "root".to_string(),
                group: "root".to_string(),
                modified: Local::now().into(),
            },
            FakeFile {
                name: "crash".to_string(),
                is_dir: true,
                size: 4096,
                permissions: "drwxrwxrwt".to_string(),
                owner: "root".to_string(),
                group: "root".to_string(),
                modified: Local.with_ymd_and_hms(2023, 12, 20, 10, 30, 0).unwrap().into(),
            },
            FakeFile {
                name: "lib".to_string(),
                is_dir: true,
                size: 4096,
                permissions: "drwxr-xr-x".to_string(),
                owner: "root".to_string(),
                group: "root".to_string(),
                modified: Local.with_ymd_and_hms(2024, 3, 5, 14, 30, 0).unwrap().into(),
            },
            FakeFile {
                name: "local".to_string(),
                is_dir: true,
                size: 4096,
                permissions: "drwxr-xr-x".to_string(),
                owner: "root".to_string(),
                group: "root".to_string(),
                modified: Local.with_ymd_and_hms(2023, 12, 15, 10, 30, 0).unwrap().into(),
            },
            FakeFile {
                name: "log".to_string(),
                is_dir: true,
                size: 4096,
                permissions: "drwxr-xr-x".to_string(),
                owner: "root".to_string(),
                group: "syslog".to_string(),
                modified: Local::now().into(),
            },
            FakeFile {
                name: "mail".to_string(),
                is_dir: true,
                size: 4096,
                permissions: "drwxrwsr-x".to_string(),
                owner: "root".to_string(),
                group: "mail".to_string(),
                modified: Local.with_ymd_and_hms(2023, 12, 15, 10, 30, 0).unwrap().into(),
            },
            FakeFile {
                name: "opt".to_string(),
                is_dir: true,
                size: 4096,
                permissions: "drwxr-xr-x".to_string(),
                owner: "root".to_string(),
                group: "root".to_string(),
                modified: Local.with_ymd_and_hms(2023, 12, 15, 10, 30, 0).unwrap().into(),
            },
            FakeFile {
                name: "spool".to_string(),
                is_dir: true,
                size: 4096,
                permissions: "drwxr-xr-x".to_string(),
                owner: "root".to_string(),
                group: "root".to_string(),
                modified: Local.with_ymd_and_hms(2024, 3, 20, 5, 30, 0).unwrap().into(),
            },
            FakeFile {
                name: "tmp".to_string(),
                is_dir: true,
                size: 4096,
                permissions: "drwxrwxrwt".to_string(),
                owner: "root".to_string(),
                group: "root".to_string(),
                modified: Local::now().into(),
            },
            FakeFile {
                name: "www".to_string(),
                is_dir: true,
                size: 4096,
                permissions: "drwxr-xr-x".to_string(),
                owner: "root".to_string(),
                group: "root".to_string(),
                modified: Local.with_ymd_and_hms(2024, 2, 28, 9, 45, 0).unwrap().into(),
            },
        ],
    });

    // /var/log directory
    filesystem.insert("/var/log".to_string(), FakeDir {
        path: "/var/log".to_string(),
        files: vec![
            FakeFile {
                name: ".".to_string(),
                is_dir: true,
                size: 4096,
                permissions: "drwxr-xr-x".to_string(),
                owner: "root".to_string(),
                group: "syslog".to_string(),
                modified: Local::now().into(),
            },
            FakeFile {
                name: "..".to_string(),
                is_dir: true,
                size: 4096,
                permissions: "drwxr-xr-x".to_string(),
                owner: "root".to_string(),
                group: "root".to_string(),
                modified: Local.with_ymd_and_hms(2024, 3, 21, 8, 0, 0).unwrap().into(),
            },
            FakeFile {
                name: "alternatives.log".to_string(),
                is_dir: false,
                size: 9320,
                permissions: "-rw-r--r--".to_string(),
                owner: "root".to_string(),
                group: "root".to_string(),
                modified: Local.with_ymd_and_hms(2024, 3, 10, 3, 45, 0).unwrap().into(),
            },
            FakeFile {
                name: "apache2".to_string(),
                is_dir: true,
                size: 4096,
                permissions: "drwxr-xr-x".to_string(),
                owner: "root".to_string(),
                group: "adm".to_string(),
                modified: Local.with_ymd_and_hms(2024, 3, 21, 0, 0, 0).unwrap().into(),
            },
            FakeFile {
                name: "apt".to_string(),
                is_dir: true,
                size: 4096,
                permissions: "drwxr-xr-x".to_string(),
                owner: "root".to_string(),
                group: "root".to_string(),
                modified: Local.with_ymd_and_hms(2024, 3, 20, 16, 15, 0).unwrap().into(),
            },
            FakeFile {
                name: "auth.log".to_string(),
                is_dir: false,
                size: 29516,
                permissions: "-rw-r-----".to_string(),
                owner: "syslog".to_string(),
                group: "adm".to_string(),
                modified: Local::now().into(),
            },
            FakeFile {
                name: "btmp".to_string(),
                is_dir: false,
                size: 1536,
                permissions: "-rw-r-----".to_string(),
                owner: "root".to_string(),
                group: "utmp".to_string(),
                modified: Local.with_ymd_and_hms(2024, 3, 21, 8, 46, 23).unwrap().into(),
            },
            FakeFile {
                name: "dpkg.log".to_string(),
                is_dir: false,
                size: 32768,
                permissions: "-rw-r--r--".to_string(),
                owner: "root".to_string(),
                group: "root".to_string(),
                modified: Local.with_ymd_and_hms(2024, 3, 20, 16, 15, 0).unwrap().into(),
            },
            FakeFile {
                name: "faillog".to_string(),
                is_dir: false,
                size: 51200,
                permissions: "-rw-r--r--".to_string(),
                owner: "root".to_string(),
                group: "root".to_string(),
                modified: Local.with_ymd_and_hms(2024, 3, 21, 8, 46, 23).unwrap().into(),
            },
            FakeFile {
                name: "kern.log".to_string(),
                is_dir: false,
                size: 38916,
                permissions: "-rw-r-----".to_string(),
                owner: "syslog".to_string(),
                group: "adm".to_string(),
                modified: Local::now().into(),
            },
            FakeFile {
                name: "lastlog".to_string(),
                is_dir: false,
                size: 292292,
                permissions: "-rw-rw-r--".to_string(),
                owner: "root".to_string(),
                group: "utmp".to_string(),
                modified: Local.with_ymd_and_hms(2024, 3, 21, 12, 30, 54).unwrap().into(),
            },
            FakeFile {
                name: "syslog".to_string(),
                is_dir: false,
                size: 107520,
                permissions: "-rw-r-----".to_string(),
                owner: "syslog".to_string(),
                group: "adm".to_string(),
                modified: Local::now().into(),
            },
            FakeFile {
                name: "wtmp".to_string(),
                is_dir: false,
                size: 12288,
                permissions: "-rw-r--r--".to_string(),
                owner: "root".to_string(),
                group: "utmp".to_string(),
                modified: Local.with_ymd_and_hms(2024, 3, 21, 12, 30, 54).unwrap().into(),
            },
        ],
    });

    // /etc directory
    filesystem.insert("/etc".to_string(), FakeDir {
        path: "/etc".to_string(),
        files: vec![
            FakeFile {
                name: ".".to_string(),
                is_dir: true,
                size: 4096,
                permissions: "drwxr-xr-x".to_string(),
                owner: "root".to_string(),
                group: "root".to_string(),
                modified: Local.with_ymd_and_hms(2024, 3, 20, 9, 15, 0).unwrap().into(),
            },
            FakeFile {
                name: "..".to_string(),
                is_dir: true,
                size: 4096,
                permissions: "drwxr-xr-x".to_string(),
                owner: "root".to_string(),
                group: "root".to_string(),
                modified: Local.with_ymd_and_hms(2023, 12, 15, 10, 30, 0).unwrap().into(),
            },
            FakeFile {
                name: "passwd".to_string(),
                is_dir: false,
                size: 2043,
                permissions: "-rw-r--r--".to_string(),
                owner: "root".to_string(),
                group: "root".to_string(),
                modified: Local.with_ymd_and_hms(2024, 3, 10, 9, 15, 0).unwrap().into(),
            },
            FakeFile {
                name: "shadow".to_string(),
                is_dir: false,
                size: 1311,
                permissions: "-rw-r-----".to_string(),
                owner: "root".to_string(),
                group: "shadow".to_string(),
                modified: Local.with_ymd_and_hms(2024, 3, 10, 9, 15, 0).unwrap().into(),
            },
            FakeFile {
                name: "group".to_string(),
                is_dir: false,
                size: 1071,
                permissions: "-rw-r--r--".to_string(),
                owner: "root".to_string(),
                group: "root".to_string(),
                modified: Local.with_ymd_and_hms(2024, 3, 10, 9, 15, 0).unwrap().into(),
            },
            FakeFile {
                name: "hostname".to_string(),
                is_dir: false,
                size: 9,
                permissions: "-rw-r--r--".to_string(),
                owner: "root".to_string(),
                group: "root".to_string(),
                modified: Local.with_ymd_and_hms(2023, 12, 15, 10, 30, 0).unwrap().into(),
            },
            FakeFile {
                name: "hosts".to_string(),
                is_dir: false,
                size: 221,
                permissions: "-rw-r--r--".to_string(),
                owner: "root".to_string(),
                group: "root".to_string(),
                modified: Local.with_ymd_and_hms(2023, 12, 15, 10, 30, 0).unwrap().into(),
            },
            FakeFile {
                name: "ssh".to_string(),
                is_dir: true,
                size: 4096,
                permissions: "drwxr-xr-x".to_string(),
                owner: "root".to_string(),
                group: "root".to_string(),
                modified: Local.with_ymd_and_hms(2024, 3, 20, 9, 00, 0).unwrap().into(),
            },
            FakeFile {
                name: "apache2".to_string(),
                is_dir: true,
                size: 4096,
                permissions: "drwxr-xr-x".to_string(),
                owner: "root".to_string(),
                group: "root".to_string(),
                modified: Local.with_ymd_and_hms(2024, 3, 1, 14, 30, 0).unwrap().into(),
            },
            FakeFile {
                name: "cron.d".to_string(),
                is_dir: true,
                size: 4096,
                permissions: "drwxr-xr-x".to_string(),
                owner: "root".to_string(),
                group: "root".to_string(),
                modified: Local.with_ymd_and_hms(2024, 2, 20, 10, 0, 0).unwrap().into(),
            },
            FakeFile {
                name: "cron.daily".to_string(),
                is_dir: true,
                size: 4096,
                permissions: "drwxr-xr-x".to_string(),
                owner: "root".to_string(),
                group: "root".to_string(),
                modified: Local.with_ymd_and_hms(2024, 2, 20, 10, 0, 0).unwrap().into(),
            },
            FakeFile {
                name: "default".to_string(),
                is_dir: true,
                size: 4096,
                permissions: "drwxr-xr-x".to_string(),
                owner: "root".to_string(),
                group: "root".to_string(),
                modified: Local.with_ymd_and_hms(2023, 12, 15, 10, 30, 0).unwrap().into(),
            },
            FakeFile {
                name: "logrotate.d".to_string(),
                is_dir: true,
                size: 4096,
                permissions: "drwxr-xr-x".to_string(),
                owner: "root".to_string(),
                group: "root".to_string(),
                modified: Local.with_ymd_and_hms(2023, 12, 15, 10, 30, 0).unwrap().into(),
            },
            FakeFile {
                name: "init.d".to_string(),
                is_dir: true,
                size: 4096,
                permissions: "drwxr-xr-x".to_string(),
                owner: "root".to_string(),
                group: "root".to_string(),
                modified: Local.with_ymd_and_hms(2023, 12, 15, 10, 30, 0).unwrap().into(),
            },
            FakeFile {
                name: "profile".to_string(),
                is_dir: false,
                size: 603,
                permissions: "-rw-r--r--".to_string(),
                owner: "root".to_string(),
                group: "root".to_string(),
                modified: Local.with_ymd_and_hms(2023, 12, 1, 0, 0, 0).unwrap().into(),
            },
            FakeFile {
                name: "sudoers".to_string(),
                is_dir: false,
                size: 4163,
                permissions: "-r--r-----".to_string(),
                owner: "root".to_string(),
                group: "root".to_string(),
                modified: Local.with_ymd_and_hms(2023, 12, 1, 0, 0, 0).unwrap().into(),
            },
        ],
    });

    // /var/www directory
    filesystem.insert("/var/www".to_string(), FakeDir {
        path: "/var/www".to_string(),
        files: vec![
            FakeFile {
                name: ".".to_string(),
                is_dir: true,
                size: 4096,
                permissions: "drwxr-xr-x".to_string(),
                owner: "root".to_string(),
                group: "root".to_string(),
                modified: Local.with_ymd_and_hms(2024, 2, 28, 9, 45, 0).unwrap().into(),
            },
            FakeFile {
                name: "..".to_string(),
                is_dir: true,
                size: 4096,
                permissions: "drwxr-xr-x".to_string(),
                owner: "root".to_string(),
                group: "root".to_string(),
                modified: Local.with_ymd_and_hms(2024, 3, 21, 8, 0, 0).unwrap().into(),
            },
            FakeFile {
                name: "html".to_string(),
                is_dir: true,
                size: 4096,
                permissions: "drwxr-xr-x".to_string(),
                owner: "www-data".to_string(),
                group: "www-data".to_string(),
                modified: Local.with_ymd_and_hms(2024, 3, 10, 12, 30, 0).unwrap().into(),
            },
        ],
    });

    // /var/www/html directory
    filesystem.insert("/var/www/html".to_string(), FakeDir {
        path: "/var/www/html".to_string(),
        files: vec![
            FakeFile {
                name: ".".to_string(),
                is_dir: true,
                size: 4096,
                permissions: "drwxr-xr-x".to_string(),
                owner: "www-data".to_string(),
                group: "www-data".to_string(),
                modified: Local.with_ymd_and_hms(2024, 3, 10, 12, 30, 0).unwrap().into(),
            },
            FakeFile {
                name: "..".to_string(),
                is_dir: true,
                size: 4096,
                permissions: "drwxr-xr-x".to_string(),
                owner: "root".to_string(),
                group: "root".to_string(),
                modified: Local.with_ymd_and_hms(2024, 2, 28, 9, 45, 0).unwrap().into(),
            },
            FakeFile {
                name: "index.html".to_string(),
                is_dir: false,
                size: 10701,
                permissions: "-rw-r--r--".to_string(),
                owner: "www-data".to_string(),
                group: "www-data".to_string(),
                modified: Local.with_ymd_and_hms(2024, 3, 10, 12, 30, 0).unwrap().into(),
            },
            FakeFile {
                name: "css".to_string(),
                is_dir: true,
                size: 4096,
                permissions: "drwxr-xr-x".to_string(),
                owner: "www-data".to_string(),
                group: "www-data".to_string(),
                modified: Local.with_ymd_and_hms(2024, 3, 10, 12, 30, 0).unwrap().into(),
            },
            FakeFile {
                name: "js".to_string(),
                is_dir: true,
                size: 4096,
                permissions: "drwxr-xr-x".to_string(),
                owner: "www-data".to_string(),
                group: "www-data".to_string(),
                modified: Local.with_ymd_and_hms(2024, 3, 10, 12, 30, 0).unwrap().into(),
            },
            FakeFile {
                name: "images".to_string(),
                is_dir: true,
                size: 4096,
                permissions: "drwxr-xr-x".to_string(),
                owner: "www-data".to_string(),
                group: "www-data".to_string(),
                modified: Local.with_ymd_and_hms(2024, 3, 10, 12, 30, 0).unwrap().into(),
            },
            FakeFile {
                name: "config.php.bak".to_string(),
                is_dir: false,
                size: 1256,
                permissions: "-rw-r--r--".to_string(),
                owner: "www-data".to_string(),
                group: "www-data".to_string(),
                modified: Local.with_ymd_and_hms(2024, 2, 20, 9, 15, 0).unwrap().into(),
            },
        ],
    });

    // Add more directories as needed...

    filesystem
}

// Main LS command handler function
pub fn handle_ls_command(cmd: &str, current_path: &str) -> String {
    // Parse command options and path
    let mut parts = cmd.trim().split_whitespace();
    parts.next(); // Skip the "ls" part

    let mut show_all = false;
    let mut long_format = false;
    let mut human_readable = false;
    let mut target_path = current_path.to_string();

    // Parse options
    for part in parts {
        if part.starts_with('-') {
            if part.contains('a') {
                show_all = true;
            }
            if part.contains('l') {
                long_format = true;
            }
            if part.contains('h') {
                human_readable = true;
            }
        } else {
            // It's a path, resolve it
            target_path = resolve_path(current_path, part);
        }
    }

    // Get directory contents
    let filesystem = FILESYSTEM.get_or_init(move || initialize_filesystem());

    if let Some(directory) = filesystem.get(&target_path) {
        return if long_format {
            format_ls_long(directory, show_all, human_readable)
        } else {
            format_ls_short(directory, show_all)
        }
    }

    // Directory not found
    format!("ls: cannot access '{}': No such file or directory", target_path)
}

// Helper function to format ls -l output
fn format_ls_long(directory: &FakeDir, show_all: bool, human_readable: bool) -> String {
    let mut result = format!("total {}\n", directory.files.len());

    for file in &directory.files {
        // Skip hidden files if not showing all
        if !show_all && file.name.starts_with('.') && file.name != "." && file.name != ".." {
            continue;
        }

        let size = if human_readable {
            format_size(file.size)
        } else {
            format!("{}", file.size)
        };

        // Format date: Apr 10 12:34 for recent files, Apr 10 2023 for older files
        let now = Utc::now();
        let file_time = file.modified;
        let date_str = if (now - file_time).num_days() < 180 {
            file_time.format("%b %e %H:%M").to_string()
        } else {
            file_time.format("%b %e %Y").to_string()
        };

        result.push_str(&format!(
            "{} {:>3} {:>8} {:>8} {:>8} {} {}\n",
            file.permissions,
            1, // Number of hard links (simplified)
            file.owner,
            file.group,
            size,
            date_str,
            file.name
        ));
    }

    result
}

// Helper function to format regular ls output
fn format_ls_short(directory: &FakeDir, show_all: bool) -> String {
    let mut files: Vec<&str> = Vec::new();

    for file in &directory.files {
        // Skip hidden files if not showing all
        if !show_all && file.name.starts_with('.') && file.name != "." && file.name != ".." {
            continue;
        }

        files.push(&file.name);
    }

    files.sort();
    files.join("  ") + "\n"
}

// Helper function to format human-readable file sizes
fn format_size(size: u64) -> String {
    if size < 1024 {
        format!("{}", size)
    } else if size < 1024 * 1024 {
        format!("{:.1}K", size as f64 / 1024.0)
    } else if size < 1024 * 1024 * 1024 {
        format!("{:.1}M", size as f64 / (1024.0 * 1024.0))
    } else {
        format!("{:.1}G", size as f64 / (1024.0 * 1024.0 * 1024.0))
    }
}

// Helper function to resolve relative paths
fn resolve_path(current_path: &str, path: &str) -> String {
    if path.starts_with('/') {
        // Absolute path
        return path.to_string();
    }

    // Simple relative path resolution
    if current_path.ends_with('/') {
        format!("{}{}", current_path, path)
    } else {
        format!("{}/{}", current_path, path)
    }
}