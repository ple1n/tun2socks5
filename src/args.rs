use crate::{Error, Result};
use clap::{Parser, Subcommand};
use nsproxy_common::UniqueFile;
use serde::{Deserialize, Serialize};
use socks5_impl::protocol::UserKey;
use std::{
    net::{IpAddr, SocketAddr, ToSocketAddrs},
    path::PathBuf,
};
use tracing::info;

#[derive(Debug, Clone, Parser, Serialize, Deserialize)]
#[command(author, version, about = "tun2socks5 application.", long_about = None)]
pub struct Args {
    /// Name of the tun interface
    #[arg(short, long, value_name = "name", default_value = if cfg!(target_os = "linux") { "tun0" } else { "utun3" })]
    pub tun: String,
    #[cfg(target_os = "linux")]
    #[arg(short, long)]
    /// Routing and system setup, which decides whether to setup the routing and system configuration
    pub setup: bool,
    /// Verbosity level
    #[arg(short, long, value_name = "level", value_enum, default_value = "info")]
    pub verbosity: ArgVerbosity,
    #[command(subcommand)]
    pub args: ArgMode,
}

#[derive(Subcommand, Serialize, Deserialize, Clone, Debug)]
#[command(name = "proxy", about = "config for tun2socks")]
pub enum ArgMode {
    /// Specify proxy config by a file
    File { path: PathBuf },
    /// Specify proxy config by cmd args
    Args(#[command(flatten)] IArgs),
}

impl ArgMode {
    pub fn to_iargs(self) -> Result<IArgs> {
        let args = self;
        let iargs: IArgs = match args {
            ArgMode::File { path } => {
                info!("Reading from {:?}", &path);
                let mut f = std::fs::File::open(path)?;
                let iargs: IArgs = serde_json::from_reader(&mut f)?;
                iargs
            }
            ArgMode::Args(args) => args,
        };
        Ok(iargs)
    }
}

#[derive(Debug, Clone, Parser, Serialize, Deserialize)]
pub struct IArgs {
    /// Proxy URL in the form proto://[username[:password]@]host:port
    #[arg(short, long, value_parser = ArgProxy::from_url, value_name = "URL")]
    pub proxy: Option<ArgProxy>,
    /// IPv6 enabled
    #[arg(short = '6', long)]
    pub ipv6_enabled: bool,

    /// DNS handling strategy
    #[arg(long, value_name = "strategy", value_enum, default_value = "handled")]
    pub dns: ArgDns,

    /// DNS resolver address
    #[arg(long, value_name = "IP", default_value = "8.8.8.8")]
    pub dns_addr: IpAddr,

    /// IPs used in routing setup which should bypass the tunnel
    #[arg(short, long, value_name = "IP")]
    pub bypass: Vec<IpAddr>,

    #[arg(long)]
    pub designated: Option<PathBuf>,
    /// for self identifying. EdgeIndex
    #[arg(long)]
    pub id: Option<usize>,
    /// for self identifying.
    /// also used as default name when creating a new node
    #[arg(long)]
    pub name: Option<String>,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, clap::ValueEnum, Deserialize, Serialize)]
pub enum ArgVerbosity {
    Off,
    Error,
    Warn,
    Info,
    Debug,
    Trace,
}

/// DNS query handling strategy
/// - OverTcp: Use TCP to send DNS queries to the DNS server
/// - Direct: Do not handle DNS by relying on DNS server bypassing
#[derive(Default, Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, clap::ValueEnum, Deserialize, Serialize)]
pub enum ArgDns {
    OverTcp,
    Direct,
    /// There is also a default value in clap
    #[default]
    Handled,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ArgProxy {
    pub proxy_type: ProxyType,
    pub addr: SocketAddr,
    pub credentials: Option<UserKey>,
}

impl ArgProxy {
    pub fn from_url(s: &str) -> Result<ArgProxy> {
        let e = format!("`{s}` is not a valid proxy URL");
        let url = url::Url::parse(s).map_err(|_| Error::from(&e))?;
        let e = format!("`{s}` does not contain a host");
        let host = url.host_str().ok_or(Error::from(e))?;

        let mut url_host = String::from(host);
        let e = format!("`{s}` does not contain a port");
        let port = url.port().ok_or(Error::from(&e))?;
        url_host.push(':');
        url_host.push_str(port.to_string().as_str());

        let e = format!("`{host}` could not be resolved");
        let mut addr_iter = url_host.to_socket_addrs().map_err(|_| Error::from(&e))?;

        let e = format!("`{host}` does not resolve to a usable IP address");
        let addr = addr_iter.next().ok_or(Error::from(&e))?;

        let credentials = if url.username() == "" && url.password().is_none() {
            None
        } else {
            let username = String::from(url.username());
            let password = String::from(url.password().unwrap_or(""));
            Some(UserKey::new(username, password))
        };

        let scheme = url.scheme();

        let proxy_type = match url.scheme().to_ascii_lowercase().as_str() {
            "socks4" => Some(ProxyType::Socks4),
            "socks5" => Some(ProxyType::Socks5),
            "http" => Some(ProxyType::Http),
            _ => None,
        }
        .ok_or(Error::from(&format!("`{scheme}` is an invalid proxy type")))?;

        Ok(ArgProxy {
            proxy_type,
            addr,
            credentials,
        })
    }
}

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Debug, Default, Deserialize, Serialize)]
pub enum ProxyType {
    Socks4,
    #[default]
    Socks5,
    Http,
}

impl std::fmt::Display for ProxyType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ProxyType::Socks4 => write!(f, "socks4"),
            ProxyType::Socks5 => write!(f, "socks5"),
            ProxyType::Http => write!(f, "http"),
        }
    }
}

#[allow(dead_code)]
pub enum NetworkInterface {
    Named(String),
    #[cfg(unix)]
    Fd(std::os::fd::RawFd),
}
