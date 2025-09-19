#![feature(let_chains)]
#![feature(decl_macro)]

use crate::{
    directions::{IncomingDataEvent, IncomingDirection, OutgoingDirection},
    dns::{DNSState, VDNSRES},
    http::HttpManager,
    session_info::{IpProtocol, SessionInfo},
};
use anyhow::{anyhow, bail};
use bytes::BytesMut;
use futures::{future::pending, SinkExt, StreamExt};
use id_alloc::NetRange;
use ipstack::{
    stream::{IpStackStream, IpStackTcpStream, IpStackUdpStream},
    IpStackConfig, TUNDev,
};
use nsproxy_common::{forever, rpc::FromClient};
use proxy_handler::{ConnectionManager, ProxyHandler};
use socks::SocksProxyManager;
use std::{
    collections::{HashMap, VecDeque},
    fmt::Debug,
    future::Future,
    io::Write,
    net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4},
    ops::{DerefMut, RangeInclusive},
    process::exit,
    sync::Arc,
    time::Duration,
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf},
    net::TcpStream,
    signal::unix::SignalKind,
    sync::{
        mpsc::{Receiver, Sender},
        Mutex, RwLock,
    },
    time::Instant,
};
use tracing::{debug, error, info, trace, warn};
use tun_rs::AsyncDevice;
use udp_stream::UdpStream;
pub use {
    args::*,
    error::{Error, Result},
    route_config::{config_restore, config_settings, DEFAULT_GATEWAY, TUN_DNS, TUN_GATEWAY, TUN_IPV4, TUN_NETMASK},
};

mod args;
mod directions;
pub mod dns;
mod error;
mod http;
mod private_ip;
mod proxy_handler;
mod route_config;
mod session_info;
mod socks;

pub use ipstack;
pub use tun_rs;

const DNS_PORT: u16 = 53;

static TASK_COUNT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
use std::sync::atomic::Ordering::Relaxed;

pub macro aok {
  ($t:ty) => {  anyhow::Result::<$t, anyhow::Error>::Ok(())},
  () => { anyhow::Result::<(), anyhow::Error>::Ok(())}
}

const POOL_SIZE: usize = 40000;

pub async fn main_entry(
    device: TUNDev,
    mtu: u16,
    packet_info: bool,
    args: IArgs,
) -> crate::Result<()> {
    use dns::VirtDNSAsync as VirtDNS;
    let server_addr = args.proxy.addr;
    let key = args.proxy.credentials.clone();
    let dns_addr = args.dns_addr;
    let ipv6_enabled = args.ipv6_enabled;
    let mut vdns = if let Some(ref pa) = args.state {
        if pa.exists() {
            let re: DNSState<String, Ipv4Addr> = bincode::deserialize_from(std::fs::File::open(pa)?)?;
            VirtDNS::from_state(POOL_SIZE, re)?
        } else {
            VirtDNS::default(POOL_SIZE)?
        }
    } else {
        VirtDNS::default(POOL_SIZE)?
    };
    if let Some(fp) = args.designated {
        info!("load user-designated name mappings from {:?}", &fp);
        let mut f = tokio::fs::File::open(fp).await?;
        let mut buf = String::new();
        f.read_to_string(&mut buf).await?;
        let desig: bimap::BiHashMap<Ipv4Addr, String> = serde_json::from_str(&buf)?;

        todo!()
    }
    use socks5_impl::protocol::Version::{V4, V5};
    let mgr = match args.proxy.proxy_type {
        ProxyType::Socks5 => Arc::new(SocksProxyManager::new(server_addr, V5, key)) as Arc<dyn ConnectionManager>,
        ProxyType::Socks4 => Arc::new(SocksProxyManager::new(server_addr, V4, key)) as Arc<dyn ConnectionManager>,
        ProxyType::Http => Arc::new(HttpManager::new(server_addr, key)) as Arc<dyn ConnectionManager>,
    };
    let conf = IpStackConfig {
        mtu,
        packet_info,
        tcp_timeout: Duration::from_secs(60),
        udp_timeout: Duration::from_secs(20),
        ..Default::default()
    };
    let vh = vdns.handle.clone();

    use nsproxy_common::rpc::*;

    let mut ip_stack = ipstack::IpStack::new(conf, device);
    info!("VirtDNS with assigned mapping: {:?}", &vdns.handle.desig);
    
    loop {
        debug!("Wait for new stream");
        let ip_stack_stream = ip_stack.accept().await?;
        match ip_stack_stream {
            IpStackStream::Tcp(tcp) => {
                // trace!("Session count {}", TASK_COUNT.fetch_add(1, Relaxed) + 1);
                let mgr = mgr.clone();
                let vh = vh.clone();
                tokio::spawn(async move {
                    if let VDNSRES::Addr(dst) = vh.process(tcp.peer_addr()) {
                        let info = SessionInfo::new(tcp.local_addr(), dst, IpProtocol::Tcp);
                        let proxy_handler = mgr.new_proxy_handler(info.clone(), false).await?;
                        if let Err(err) = handle_tcp_session(tcp, server_addr, proxy_handler).await {
                            // This kind of error causes mid-connection drop.
                            // An error in TCP is handled by state transition internally.
                            error!("Error that causes drop. {} {:?}", info, err);
                        }
                    } else {
                        warn!("Invalid VirtDNS Addr {}", tcp.peer_addr());
                    }
                    anyhow::Ok(())
                    // trace!("Session count {}", TASK_COUNT.fetch_sub(1, Relaxed) - 1);
                });
            }
            IpStackStream::Udp(mut udp) => {
                // trace!("Session count {}", TASK_COUNT.fetch_add(1, Relaxed) + 1);
                if let VDNSRES::Addr(dst) = vh.process(udp.peer_addr()) {
                    let port = dst.port();
                    // if dst.port() == DNS_PORT {
                    //     if private_ip::is_private_ip(dst.ip()) {
                    //         dst.set_ip(dns_addr);
                    //     }
                    // }
                    let info = SessionInfo::new(udp.local_addr(), dst, IpProtocol::Udp);
                    if port == DNS_PORT {
                        match args.dns {
                            ArgDns::OverTcp => {
                                let proxy_handler = mgr.new_proxy_handler(info.clone(), false).await?;
                                tokio::spawn(async move {
                                    if let Err(err) = handle_dns_over_tcp_session(udp, server_addr, proxy_handler, ipv6_enabled).await {
                                        error!("{} error \"{:?}\"", info, err);
                                    }
                                    // trace!("Session count {}", TASK_COUNT.fetch_sub(1, Relaxed) - 1);
                                });
                                continue;
                            }
                            ArgDns::Handled => {
                                let vh = vh.clone();
                                info!("virtdns spawn to reply");
                                tokio::spawn(async move {
                                    let vh = vh;
                                    let mut pack = BytesMut::with_capacity(256);
                                    while udp.read_buf(&mut pack).await? > 0 {
                                        let k = vh.receive_query(&pack);
                                        if let Ok(k) = k {
                                            udp.write_all(&k).await?;
                                        } else {
                                            error!("udp:dns error decoding {:?}", k);
                                        }
                                        pack.clear();
                                    }
                                    crate::Result::<()>::Ok(())
                                });
                                continue;
                            }
                            ArgDns::Direct => {}
                        }
                    }
                    let proxy_handler = mgr.new_proxy_handler(info.clone(), true).await?;
                    tokio::spawn(async move {
                        if let Err(err) = handle_udp_associate_session(udp, server_addr, proxy_handler, ipv6_enabled).await {
                            error!("{} error \"{:?}\"", info, err);
                        }
                        // trace!("Session count {}", TASK_COUNT.fetch_sub(1, Relaxed) - 1);
                    });
                } else {
                    warn!("Invalid VirtDNS Addr {}", udp.peer_addr());
                }
            }
        }
    }
    if let Some(ref pa) = args.state {
        // let dump = vh.to_state().await;
        // let by = bincode::serialize(&dump)?;
        // tokio::fs::write(pa, &by).await?;
        info!("State dumped");
    }

    Ok(())
}

async fn handle_tcp_session(
    mut tcp_stack: IpStackTcpStream,
    server_addr: SocketAddr,
    proxy_handler: Arc<Mutex<dyn ProxyHandler>>,
) -> crate::Result<()> {
    let mut server = TcpStream::connect(server_addr).await?;
    info!("connected proxy at {} for {}", &server_addr, &tcp_stack);
    // let session_info = proxy_handler.lock().await.get_session_info();
    // debug!("beginning {}", session_info);

    let _ = handle_proxy_session(&mut server, proxy_handler).await?;

    // if false {
    //     handle_tcp_session_debug(tcp_stack, server).await?;
    // } else {
    //     let (mut t_rx, mut t_tx) = tokio::io::split(tcp_stack);
    //     let (mut s_rx, mut s_tx) = tokio::io::split(server);

    //     let res = tokio::try_join!(
    //         async {
    //             let k = tokio::io::copy(&mut t_rx, &mut s_tx).await?;
    //             anyhow::Ok(k)
    //         },
    //         async {
    //             let k = tokio::io::copy(&mut s_rx, &mut t_tx).await?;
    //             anyhow::Ok(k)
    //         }
    //     );
    //     debug!("ending {} with {:?}", session_info, res);
    // };

    tokio::io::copy_bidirectional(&mut tcp_stack, &mut server).await?;

    Ok(())
}

async fn handle_tcp_session_debug(tcp_stack: IpStackTcpStream, server: TcpStream) -> crate::Result<()> {
    let (mut t_rx, mut t_tx) = tokio::io::split(tcp_stack);
    let (mut s_rx, mut s_tx) = tokio::io::split(server);

    let res = tokio::try_join!(
        async {
            let mut buf = vec![0; 10000];
            loop {
                let n = t_rx.read(&mut buf).await?;
                if n == 0 {
                    break;
                }
                info!("read {} from user {:?}", n, &buf[..10]);
                s_tx.write_all(&buf[..n]).await?;
                info!("sent {} to proxy {:?}", n, &buf[..10]);
                s_tx.flush().await?;
                info!("flush {:?} to proxy", &buf[..10]);
            }
            anyhow::Ok(())
        },
        async {
            let mut buf = vec![0; 10000];
            loop {
                let n = s_rx.read(&mut buf).await?;
                if n == 0 {
                    break;
                }
                info!("read {} from proxy {:?}", n, &buf[..10]);
                t_tx.write_all(&buf[..n]).await?;
                info!("sent {} to user {:?}", n, &buf[..10]);
                t_tx.flush().await?;
                info!("flush {} to user {:?}", n, &buf[..10]);
            }
            anyhow::Ok(())
        }
    );

    res?;

    Ok(())
}

async fn handle_udp_associate_session(
    mut udp_stack: IpStackUdpStream,
    server_addr: SocketAddr,
    proxy_handler: Arc<Mutex<dyn ProxyHandler>>,
    ipv6_enabled: bool,
) -> crate::Result<()> {
    use socks5_impl::protocol::{StreamOperation, UdpHeader};
    let mut server = TcpStream::connect(server_addr).await?;
    let session_info = proxy_handler.lock().await.get_session_info();
    debug!("{}", session_info);

    let udp_addr = handle_proxy_session(&mut server, proxy_handler).await?;

    let udp_addr = udp_addr.ok_or(anyhow!("udp associate failed"))?;

    let mut udp_server = UdpStream::connect(udp_addr).await?;

    let mut buf1 = [0_u8; 4096];
    let mut buf2 = [0_u8; 4096];
    loop {
        tokio::select! {
            len = udp_stack.read(&mut buf1) => {
                let len = len?;
                if len == 0 {
                    break;
                }
                let buf1 = &buf1[..len];

                // Add SOCKS5 UDP header to the incoming data
                let mut s5_udp_data = Vec::<u8>::new();
                UdpHeader::new(0, session_info.dst.clone().into()).write_to_stream(&mut s5_udp_data)?;
                s5_udp_data.extend_from_slice(buf1);

                udp_server.write_all(&s5_udp_data).await?;
            }
            len = udp_server.read(&mut buf2) => {
                let len = len?;
                if len == 0 {
                    break;
                }
                let buf2 = &buf2[..len];

                // Remove SOCKS5 UDP header from the server data
                let header = UdpHeader::retrieve_from_stream(&mut &buf2[..])?;
                let data = &buf2[header.len()..];

                let buf = if session_info.dst.port() == DNS_PORT {
                    let mut message = dns::parse_data_to_dns_message(data, false)?;
                    if !ipv6_enabled {
                        dns::remove_ipv6_entries(&mut message);
                    }
                    message.to_vec()?
                } else {
                    data.to_vec()
                };

                udp_stack.write_all(&buf).await?;
            }
        }
    }

    Ok(())
}

async fn handle_dns_over_tcp_session(
    mut udp_stack: IpStackUdpStream,
    server_addr: SocketAddr,
    proxy_handler: Arc<Mutex<dyn ProxyHandler>>,
    ipv6_enabled: bool,
) -> crate::Result<()> {
    let mut server = TcpStream::connect(server_addr).await?;
    let session_info = proxy_handler.lock().await.get_session_info();
    info!("DNS over TCP {}", session_info);
    let _ = handle_proxy_session(&mut server, proxy_handler).await?;

    let mut buf1 = [0_u8; 4096];
    let mut buf2 = [0_u8; 4096];
    loop {
        tokio::select! {
            len = udp_stack.read(&mut buf1) => {
                let len = len?;
                if len == 0 {
                    break;
                }
                let buf1 = &buf1[..len];

                _ = dns::parse_data_to_dns_message(buf1, false)?;

                // Insert the DNS message length in front of the payload
                let len = u16::try_from(buf1.len())?;
                let mut buf = Vec::with_capacity(std::mem::size_of::<u16>() + usize::from(len));
                buf.extend_from_slice(&len.to_be_bytes());
                buf.extend_from_slice(buf1);

                server.write_all(&buf).await?;
            }
            len = server.read(&mut buf2) => {
                let len = len?;
                if len == 0 {
                    break;
                }
                let mut buf = buf2[..len].to_vec();

                let mut to_send: VecDeque<Vec<u8>> = VecDeque::new();
                loop {
                    if buf.len() < 2 {
                        break;
                    }
                    let len = u16::from_be_bytes([buf[0], buf[1]]) as usize;
                    if buf.len() < len + 2 {
                        break;
                    }

                    // remove the length field
                    let data = buf[2..len + 2].to_vec();

                    let mut message = dns::parse_data_to_dns_message(&data, false)?;

                    let name = dns::extract_domain_from_dns_message(&message)?;
                    let ip = dns::extract_ipaddr_from_dns_message(&message);
                    trace!("DNS over TCP query result: {} -> {:?}", name, ip);

                    if !ipv6_enabled {
                        dns::remove_ipv6_entries(&mut message);
                    }

                    to_send.push_back(message.to_vec()?);
                    if len + 2 == buf.len() {
                        break;
                    }
                    buf = buf[len + 2..].to_vec();
                }

                while let Some(packet) = to_send.pop_front() {
                    udp_stack.write_all(&packet).await?;
                }
            }
        }
    }

    Ok(())
}

/// Read/write to server until connection has been established
async fn handle_proxy_session(server: &mut TcpStream, proxy_handler: Arc<Mutex<dyn ProxyHandler>>) -> crate::Result<Option<SocketAddr>> {
    let mut launched = false;
    let mut proxy_handler = proxy_handler.lock().await;
    let dir = OutgoingDirection::ToServer;

    loop {
        if proxy_handler.connection_established() {
            break;
        }

        if !launched {
            let data = proxy_handler.peek_data(dir).buffer;
            let len = data.len();
            if len == 0 {
                bail!("proxy_handler launched went wrong")
            }
            server.write_all(data).await?;
            proxy_handler.consume_data(dir, len);

            launched = true;
        }

        let mut buf = [0_u8; 4096];
        let len = server.read(&mut buf).await?;
        if len == 0 {
            error!("{:?}", proxy_handler);
            bail!("proxy server closed unexpectedly")
        }
        let event = IncomingDataEvent {
            direction: IncomingDirection::FromServer,
            buffer: &buf[..len],
        };
        proxy_handler.push_data(event).await?;

        let data = proxy_handler.peek_data(dir).buffer;
        let len = data.len();
        if len > 0 {
            server.write_all(data).await?;
            proxy_handler.consume_data(dir, len);
        }
    }
    Ok(proxy_handler.get_udp_associate())
}
