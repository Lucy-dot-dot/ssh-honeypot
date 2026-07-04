use async_trait::async_trait;
use super::command_trait::{Command, CommandResult};
use super::context::CommandContext;
use chrono::{Local, Utc};

/// Date command implementation using the new trait system
pub struct DateCommand;

#[async_trait]
impl Command for DateCommand {
    fn name(&self) -> &'static str {
        "date"
    }
    
    fn help(&self) -> String {
        "Usage: date [OPTION]... [+FORMAT]\n\
        Display the current time in the given FORMAT, or set the system date.\n\
        \n\
        Mandatory arguments to long options are mandatory for short options too.\n\
        -d, --date=STRING         display time described by STRING, not 'now'\n\
        -f, --file=DATEFILE       like --date once for each line of DATEFILE\n\
        -I[TIMESPEC], --iso-8601[=TIMESPEC]  output date/time in ISO 8601 format.\n\
        -r, --reference=FILE      display the last modification time of FILE\n\
        -R, --rfc-2822            output date and time in RFC 2822 format.\n\
        --rfc-3339=TIMESPEC       output date and time in RFC 3339 format.\n\
        -s, --set=STRING          set time described by STRING\n\
        -u, --utc, --universal    print or set Coordinated Universal Time (UTC)\n\
        --help                    display this help and exit\n\
        --version                 output version information and exit\n\
        \n\
        FORMAT controls the output.  Interpreted sequences are:\n\
        %a     locale's abbreviated weekday name (e.g., Sun)\n\
        %A     locale's full weekday name (e.g., Sunday)\n\
        %b     locale's abbreviated month name (e.g., Jan)\n\
        %B     locale's full month name (e.g., January)\n\
        %c     locale's date and time (e.g., Thu Mar  3 23:05:25 2005)\n\
        %d     day of month (e.g., 01)\n\
        %D     date; same as %m/%d/%y\n\
        %H     hour (00..23)\n\
        %I     hour (01..12)\n\
        %m     month (01..12)\n\
        %M     minute (00..59)\n\
        %S     second (00..60)\n\
        %T     time; same as %H:%M:%S\n\
        %y     last two digits of year (00..99)\n\
        %Y     year\n\
        %z     +hhmm numeric time zone (e.g., -0400)\n\
        %Z     alphabetic time zone abbreviation (e.g., EDT)\n".to_string()
    }
    
    fn version(&self) -> String {
        "date (GNU coreutils) 8.32\n\
        License GPLv3+: GNU GPL version 3 or later <https://gnu.org/licenses/gpl.html>.\n\
        This is free software: you are free to change and redistribute it.\n\
        There is NO WARRANTY, to the extent permitted by law.\n".to_string()
    }
    
    async fn execute(&self, args: &[String], _context: &mut CommandContext) -> CommandResult {
        // Default settings
        let mut utc_time = false;
        let mut iso_format = false;
        let mut rfc_format = false;
        let mut custom_format: Option<String> = None;
        let mut print_help = false;
        let mut print_version = false;

        // Parse arguments
        for arg in args {
            if arg == "--help" {
                print_help = true;
            } else if arg == "--version" {
                print_version = true;
            } else if arg == "--utc" || arg == "-u" || arg == "--universal" {
                utc_time = true;
            } else if arg == "--iso-8601" || arg == "-I" || arg.starts_with("--iso-8601=") || arg.starts_with("-I") {
                iso_format = true;
            } else if arg == "--rfc-3339" || arg == "-R" || arg == "--rfc-2822" || arg.starts_with("--rfc-3339=") {
                rfc_format = true;
            } else if let Some(fmt) = arg.strip_prefix('+') {
                custom_format = Some(fmt.to_string());
            }
        }

        if print_help {
            return Ok(self.help());
        }

        if print_version {
            return Ok(self.version());
        }
        
        // Get the current time
        let now = if utc_time {
            Utc::now().format("%a %b %e %H:%M:%S UTC %Y").to_string()
        } else {
            let local_now = Local::now();
            
            if iso_format {
                local_now.format("%Y-%m-%d").to_string()
            } else if rfc_format {
                local_now.format("%Y-%m-%d %H:%M:%S%:z").to_string()
            } else if let Some(format) = custom_format {
                // Convert common format specifiers
                let format = format
                    .replace("%a", "%a")  // Short weekday
                    .replace("%A", "%A")  // Full weekday
                    .replace("%b", "%b")  // Short month
                    .replace("%B", "%B")  // Full month
                    .replace("%c", "%a %b %e %H:%M:%S %Y")  // Complete date/time
                    .replace("%d", "%d")  // Day of month (01-31)
                    .replace("%D", "%m/%d/%y")  // Date as mm/dd/yy
                    .replace("%H", "%H")  // Hour (00-23)
                    .replace("%I", "%I")  // Hour (01-12)
                    .replace("%m", "%m")  // Month (01-12)
                    .replace("%M", "%M")  // Minute (00-59)
                    .replace("%S", "%S")  // Second (00-60)
                    .replace("%T", "%H:%M:%S")  // Time as HH:MM:SS
                    .replace("%y", "%y")  // Year without century (00-99)
                    .replace("%Y", "%Y")  // Year with century
                    .replace("%z", "%z")  // Timezone offset (+HHMM)
                    .replace("%Z", "%Z");  // Timezone name
                
                local_now.format(&format).to_string()
            } else {
                // Default format: "Wed Jan 20 14:35:46 EST 2021"
                local_now.format("%a %b %e %H:%M:%S %Z %Y").to_string()
            }
        };
        
        Ok(format!("{}\r\n", now))
    }
}