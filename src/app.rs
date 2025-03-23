use std::net::{SocketAddr, Ipv4Addr, Ipv6Addr};
use std::path::PathBuf;

#[derive(clap::Parser, Debug)]
#[command(version, about = "A small ssh server that allows for advanced honeypot usage", long_about = "A small ssh server  that allows for advanced honeypot usage. It provides a fake command interface mimicking ubuntu without any fear of malicious code execution, since no commands are actually executed. It also records all commands in a central sqlite database")]
pub struct App {
    /// The port to listen on, requires to be over 1000 or use linux setcap cap_net_bind_service command
    #[arg(short = 'i', long = "interface", default_values_t = vec![SocketAddr::new(std::net::IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), 2222), SocketAddr::new(std::net::IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 0)), 2222)], env = "INTERFACE")]
    pub interfaces: Vec<SocketAddr>,

    #[arg(short = 'd', long = "db", default_value = "honeypot.db", env = "DATABASE_PATH")]
    pub db_path: PathBuf,

    /// Disable the fake cli interface provided and only save passwords and/or key authentication attempts
    #[arg(short = 'c', long = "disable-cli-interface", default_value_t = false, env = "DISABLE_CLI_INTERFACE")]
    pub disable_cli_interface: bool,
    
    /// Authentication banner to show. Can make the server more realistic
    #[arg(short, long, env = "AUTHENTICATION_BANNER")]
    pub authentication_banner: Option<String>,
}