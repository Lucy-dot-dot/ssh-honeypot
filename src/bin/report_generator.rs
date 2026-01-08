use clap::Parser;
use ssh_honeypot::db::initialize_database_pool;
use ssh_honeypot::report::{ReportGenerator, ReportFormat};
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(version, about = "SSH Honeypot Report Generator", long_about = "Generate reports for SSH honeypot data based on IP addresses")]
struct Args {
    /// IP address to generate report for
    #[arg(short, long, required = true, env = "IP_ADDRESS")]
    ip: String,

    /// Report format (text, html, markdown)
    #[arg(short, long, default_value = "text", env = "REPORT_FORMAT")]
    format: ReportFormat,

    /// Output file path (if not specified, prints to stdout)
    #[arg(short, long, env = "OUTPUT_FILE_PATH")]
    output: Option<PathBuf>,

    /// PostgreSQL database connection URL
    #[arg(short, long, env = "DATABASE_URL", default_value = "postgresql://honeypot:honeypot@localhost:5432/ssh_honeypot")]
    database_url: String,

    /// Data source view/table to query from
    #[arg(short, long, default_value = "auth_password_enriched", env = "SOURCE")]
    source: String,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::builder()
        .parse_env(env_logger::Env::default())
        .filter_level(log::LevelFilter::Info)
        .filter_module("sqlx", log::LevelFilter::Warn)
        .init();

    let args = Args::parse();

    // Initialize database connection
    let pool = initialize_database_pool(&args.database_url, true).await?;

    // Create report generator
    let generator = ReportGenerator::new(pool);

    // Generate report
    let report = generator.generate_ip_report(&args.ip, &args.format).await?;

    // Output report
    if let Some(output_path) = args.output {
        std::fs::write(&output_path, &report)?;
        println!("Report written to: {}", output_path.display());
    } else {
        print!("{}", report);
    }

    Ok(())
}