use clap::{Args as ClapArgs, Parser, Subcommand};
use ssh_honeypot::db::initialize_database_pool;
use ssh_honeypot::report::{ReportGenerator, ReportFormat};
use std::path::PathBuf;


#[derive(ClapArgs, Debug, Clone)]
pub struct CommonArgs {
    /// Report format (text, html, markdown)
    #[arg(short, long, default_value = "text", env = "REPORT_FORMAT", global = true)]
    format: ReportFormat,

    /// Output file path (if not specified, prints to stdout)
    #[arg(short, long, env = "OUTPUT_FILE_PATH", global = true)]
    output: Option<PathBuf>,

    /// PostgreSQL database connection URL
    #[arg(short, long, env = "DATABASE_URL", default_value = "postgresql://honeypot:honeypot@localhost:5432/ssh_honeypot", global = true)]
    database_url: String,
}

#[derive(Debug, Clone, Subcommand)]
pub enum ReportMode {
    Ip {
        /// IP address to generate report for
        #[arg(env = "IP_ADDRESS")]
        ip: String,
    },
    Password {
        /// Password to generate report for
        #[arg(env = "PASSWORD")]
        password: String,
    },
}

#[derive(Parser, Debug)]
#[command(version, about = "SSH Honeypot Report Generator", long_about = "Generate reports for SSH honeypot data based on IP addresses or passwords")]
struct Args {
    /// Report mode (ip or password)
    #[command(subcommand)]
    mode: ReportMode,

    #[command(flatten)]
    args: CommonArgs
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::builder()
        .parse_env(env_logger::Env::default())
        .filter_level(log::LevelFilter::Info)
        .filter_module("sqlx", log::LevelFilter::Warn)
        .init();

    let args = Args::parse();

    let pool = initialize_database_pool(&args.args.database_url, true).await?;
    let generator = ReportGenerator::new(pool);

    let report = match args.mode {
        ReportMode::Ip { ip } => {
            generator.generate_ip_report(&ip, &args.args.format).await?
        }
        ReportMode::Password { password } => {
            generator.generate_password_report(&password, &args.args.format).await?
        }
    };

    // Output report
    if let Some(output_path) = args.args.output {
        std::fs::write(&output_path, &report)?;
        println!("Report written to: {}", output_path.display());
    } else {
        print!("{}", report);
    }

    Ok(())
}