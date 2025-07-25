use std::net::{SocketAddr, Ipv4Addr, Ipv6Addr};
use std::path::PathBuf;
use clap::ArgAction;

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

    /// Makes the response veryyyyy slooooooooooowww in order to slow down attackers and "tarpit" them
    #[arg(short, long, env = "TARPIT", default_value_t = false, action = ArgAction::SetTrue)]
    pub tarpit: bool,

    /// Disables the base tar.gz loading, which is used to load the base system
    #[arg(short = 'g', long, env = "DISABLE_BASE_TAR_GZ_LOADING", default_value_t = false, action = ArgAction::SetTrue)]
    pub disable_base_tar_gz_loading: bool,

    /// The path to the base tar.gz file to load. Default is a debian 12 deboostrap'ed base system
    #[arg(short = 'b', long, env = "BASE_TAR_GZ_PATH", default_value = "base.tar.gz")]
    pub base_tar_gz_path: PathBuf,

    /// Key folder
    #[arg(short = 'k', long, env = "KEY_FOLDER", default_value = "/tmp")]
    pub key_folder: PathBuf,

    /// Disable SO_REUSEPORT for ssh tcp socket
    /// Disabling this may result in issues with IPv6 Ports. Can be disabled safely if net.ipv6.bindv6only = 1 is set
    #[arg(short = 'r', long, env = "DISABLE_SO_REUSEPORT", default_value_t = false, action = ArgAction::SetTrue)]
    pub disable_so_reuseport: bool,

    /// Disable SO_REUSEADDR for ssh tcp socket
    /// Disabling this may result in issues with IPv6 Ports. Can be disabled safely if net.ipv6.bindv6only = 1 is set
    #[arg(short = 's', long, env = "DISABLE_SO_REUSEADDR", default_value_t = false, action = ArgAction::SetTrue)]
    pub disable_so_reuseaddr: bool,
}