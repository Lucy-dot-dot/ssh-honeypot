use rand::{Rng, rng};

/// Represents simulated system memory usage
struct MemoryStats {
    total_mem: u64,      // Total memory in KB
    used_mem: u64,       // Used memory in KB
    free_mem: u64,       // Free memory in KB
    shared_mem: u64,     // Shared memory in KB
    buff_cache_mem: u64, // Buffer/cache memory in KB
    available_mem: u64,  // Available memory in KB

    total_swap: u64,     // Total swap in KB
    used_swap: u64,      // Used swap in KB
    free_swap: u64,      // Free swap in KB
}

impl MemoryStats {
    /// Generate realistic system memory stats
    fn generate() -> Self {
        let mut rng = rng();

        // Generate values in a realistic and consistent way
        // Memory values in KB
        let total_mem = rng.random_range(2_000_000..16_000_000); // 2GB to 16GB
        let buff_cache_mem = total_mem * rng.random_range(5..25) / 100; // 5-25% for buffers/cache
        let used_raw = total_mem * rng.random_range(30..70) / 100; // 30-70% usage
        let used_mem = used_raw - buff_cache_mem; // Used minus buffers/cache
        let free_mem = total_mem - used_raw;
        let shared_mem = total_mem * rng.random_range(1..10) / 100; // 1-10% shared
        let available_mem = free_mem + buff_cache_mem * 8 / 10; // Most of buff/cache is available

        // Swap values
        let total_swap = total_mem / 2; // Typical swap size
        let used_swap = if rng.random_bool(0.7) {
            // 70% chance of minimal swap usage
            rng.random_range(0..total_swap / 20)
        } else {
            // 30% chance of significant swap usage
            rng.random_range(total_swap / 10..total_swap / 2)
        };
        let free_swap = total_swap - used_swap;

        MemoryStats {
            total_mem,
            used_mem,
            free_mem,
            shared_mem,
            buff_cache_mem,
            available_mem,
            total_swap,
            used_swap,
            free_swap,
        }
    }
}

/// Handles the free command with various flags
pub fn handle_free_command(cmd: &str) -> String {
    let memory_stats = MemoryStats::generate();

    // Parse flags
    let parts: Vec<&str> = cmd.split_whitespace().collect();

    // Default to kilobytes if no flags specified
    let mut show_human_readable = false;
    let mut show_total = false;
    let mut show_wide = false;
    let mut unit_divisor = 1; // Default is kilobytes (divisor=1)
    let mut unit_label = "kB";

    for part in parts.iter().skip(1) {
        match *part {
            "-h" | "--human" => {
                show_human_readable = true;
                unit_divisor = 1024; // Will adjust dynamically during formatting
            },
            "-b" | "--bytes" => {
                unit_divisor = 1;
                unit_label = "B";
            },
            "-k" | "--kilo" => {
                unit_divisor = 1;
                unit_label = "kB";
            },
            "-m" | "--mega" => {
                unit_divisor = 1024;
                unit_label = "MB";
            },
            "-g" | "--giga" => {
                unit_divisor = 1024 * 1024;
                unit_label = "GB";
            },
            "--tera" => {
                unit_divisor = 1024 * 1024 * 1024;
                unit_label = "TB";
            },
            "-t" | "--total" => {
                show_total = true;
            },
            "-w" | "--wide" => {
                show_wide = true;
            },
            _ => {}
        }
    }

    // Format output based on flags
    if show_human_readable {
        format_human_readable(&memory_stats, show_total, show_wide)
    } else {
        format_with_unit(&memory_stats, unit_divisor, unit_label, show_total, show_wide)
    }
}

/// Format memory values with a specific unit
fn format_with_unit(stats: &MemoryStats, divisor: u64, unit_label: &str, show_total: bool, wide: bool) -> String {
    let mut result = String::new();

    // Column headers based on wide flag
    if wide {
        result.push_str(&format!("{:16}{:16}{:16}{:16}{:16}{:16}{:16}\r\n",
                                 "", "total", "used", "free", "shared", "buff/cache", "available"));
    } else {
        result.push_str(&format!("{:16}{:16}{:16}{:16}{:16}{:16}{:16}\r\n",
                                 "", "total", "used", "free", "shared", "buff/cache", "available"));
    }

    // Format values with the given unit
    let format_value = |value: u64| -> String {
        if divisor == 1 {
            format!("{} {}", value, unit_label)
        } else {
            format!("{} {}", value / divisor, unit_label)
        }
    };

    // Memory line
    result.push_str(&format!("{:<16}{:>10}{:>12}{:>12}{:>12}{:>12}{:>12}\r\n",
                             "Mem:",
                             format_value(stats.total_mem),
                             format_value(stats.used_mem),
                             format_value(stats.free_mem),
                             format_value(stats.shared_mem),
                             format_value(stats.buff_cache_mem),
                             format_value(stats.available_mem)
    ));

    // Swap line
    result.push_str(&format!("{:<16}{:>10}{:>12}{:>12}\r\n",
                             "Swap:",
                             format_value(stats.total_swap),
                             format_value(stats.used_swap),
                             format_value(stats.free_swap)
    ));

    // Total line (optional)
    if show_total {
        result.push_str(&format!("{:<16}{:>10}{:>12}{:>12}\r\n",
                                 "Total:",
                                 format_value(stats.total_mem + stats.total_swap),
                                 format_value(stats.used_mem + stats.used_swap),
                                 format_value(stats.free_mem + stats.free_swap)
        ));
    }

    result
}

/// Format memory values in human-readable format (with appropriate units)
fn format_human_readable(stats: &MemoryStats, show_total: bool, wide: bool) -> String {
    let mut result = String::new();

    // Column headers based on wide flag
    if wide {
        result.push_str(&format!("{:16}{:16}{:16}{:16}{:16}{:16}{:16}\r\n",
                                 "", "total", "used", "free", "shared", "buff/cache", "available"));
    } else {
        result.push_str(&format!("{:16}{:16}{:16}{:16}{:16}{:16}{:16}\r\n",
                                 "", "total", "used", "free", "shared", "buff/cache", "available"));
    }

    // Helper to format values in human-readable form
    let format_human = |value_kb: u64| -> String {
        if value_kb < 1024 {
            format!("{}K", value_kb)
        } else if value_kb < 1024 * 1024 {
            format!("{:.1}M", value_kb as f64 / 1024.0)
        } else {
            format!("{:.1}G", value_kb as f64 / (1024.0 * 1024.0))
        }
    };

    // Memory line
    result.push_str(&format!("{:<16}{:>8}{:>12}{:>12}{:>12}{:>12}{:>12}\r\n",
                             "Mem:",
                             format_human(stats.total_mem),
                             format_human(stats.used_mem),
                             format_human(stats.free_mem),
                             format_human(stats.shared_mem),
                             format_human(stats.buff_cache_mem),
                             format_human(stats.available_mem)
    ));

    // Swap line
    result.push_str(&format!("{:<16}{:>8}{:>12}{:>12}\r\n",
                             "Swap:",
                             format_human(stats.total_swap),
                             format_human(stats.used_swap),
                             format_human(stats.free_swap)
    ));

    // Total line (optional)
    if show_total {
        result.push_str(&format!("{:<16}{:>8}{:>12}{:>12}\r\n",
                                 "Total:",
                                 format_human(stats.total_mem + stats.total_swap),
                                 format_human(stats.used_mem + stats.used_swap),
                                 format_human(stats.free_mem + stats.free_swap)
        ));
    }

    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_memory_stats_generation() {
        let stats = MemoryStats::generate();

        // Basic sanity checks
        assert!(stats.total_mem >= 2_000_000 && stats.total_mem <= 16_000_000);
        assert!(stats.used_mem + stats.free_mem <= stats.total_mem);
        assert_eq!(stats.total_swap, stats.used_swap + stats.free_swap);
        assert!(stats.available_mem <= stats.total_mem);
    }

    #[test]
    fn test_basic_free_command() {
        let output = handle_free_command("free");
        assert!(output.contains("Mem:"));
        assert!(output.contains("Swap:"));
        assert!(output.contains("kB"));
    }

    #[test]
    fn test_human_readable_flag() {
        let output = handle_free_command("free -h");
        assert!(output.contains("G") || output.contains("M") || output.contains("K"));
    }

    #[test]
    fn test_unit_flags() {
        let bytes = handle_free_command("free -b");
        assert!(bytes.contains("B"));

        let mega = handle_free_command("free -m");
        assert!(mega.contains("MB"));

        let giga = handle_free_command("free -g");
        assert!(giga.contains("GB"));
    }

    #[test]
    fn test_total_flag() {
        let output = handle_free_command("free -t");
        assert!(output.contains("Total:"));
    }

    #[test]
    fn test_wide_flag() {
        let output = handle_free_command("free -w");
        assert!(output.contains("buff/cache"));
        assert!(output.contains("available"));
    }

    #[test]
    fn test_combined_flags() {
        let output = handle_free_command("free -h -t -w");
        assert!(output.contains("Total:"));
        assert!(output.contains("buff/cache"));
        assert!(output.contains("G") || output.contains("M") || output.contains("K"));
    }
}