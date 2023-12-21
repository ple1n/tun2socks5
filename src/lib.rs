#![feature(let_chains)]

use crate::{
    directions::{IncomingDataEvent, IncomingDirection, OutgoingDirection},
    dns::{DNSState, VirtDNS, VDNSRES},
    http::HttpManager,
    session_info::{IpProtocol, SessionInfo},
};
use anyhow::{anyhow, bail};
use bytes::BytesMut;
use id_alloc::NetRange;
use ipstack::{
    stream::{IpStackStream, IpStackTcpStream, IpStackUdpStream},
    IpStackConfig,
};
use log::warn;
use proxy_handler::{ConnectionManager, ProxyHandler};
use socks::SocksProxyManager;
use std::{
    collections::{HashMap, VecDeque},
    net::{Ipv4Addr, SocketAddr, SocketAddrV4},
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
};
use udp_stream::UdpStream;
pub use {
    args::*,
    error::{Error, Result},
    route_config::{config_restore, config_settings, DEFAULT_GATEWAY, TUN_DNS, TUN_GATEWAY, TUN_IPV4, TUN_NETMASK},
};

mod args;
mod directions;
mod dns;
mod error;
mod http;
mod lru;
mod private_ip;
mod proxy_handler;
mod route_config;
mod session_info;
mod socks;

const DNS_PORT: u16 = 53;

static TASK_COUNT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
use std::sync::atomic::Ordering::Relaxed;

pub async fn main_entry<D>(
    device: D,
    mtu: u16,
    packet_info: bool,
    args: IArgs,
    mut quit: Receiver<()>,
    quit_sx: Sender<()>,
) -> crate::Result<()>
where
    D: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let server_addr = args.proxy.addr;
    let key = args.proxy.credentials.clone();
    let dns_addr = args.dns_addr;
    let ipv6_enabled = args.ipv6_enabled;
    let vdns = Some(
        if let Some(ref pa) = args.state
            && pa.exists()
        {
            let re: DNSState<String, Ipv4Addr> = bincode::deserialize_from(std::fs::File::open(pa)?)?;
            VirtDNS::from_state(4096, re)?
        } else {
            VirtDNS::default(4096)?
        },
    );
    let vdns = Arc::new(RwLock::new(vdns));
    use socks5_impl::protocol::Version::{V4, V5};
    let mgr = match args.proxy.proxy_type {
        ProxyType::Socks5 => Arc::new(SocksProxyManager::new(server_addr, V5, key)) as Arc<dyn ConnectionManager>,
        ProxyType::Socks4 => Arc::new(SocksProxyManager::new(server_addr, V4, key)) as Arc<dyn ConnectionManager>,
        ProxyType::Http => Arc::new(HttpManager::new(server_addr, key)) as Arc<dyn ConnectionManager>,
    };
    let conf = IpStackConfig {
        mtu,
        packet_info,
        tcp_timeout: Duration::from_secs(3600),
        udp_timeout: Duration::from_secs(3600),
        ..Default::default()
    };

    let vd2 = vdns.clone();
    tokio::spawn(async move {
        tokio::signal::unix::signal(SignalKind::terminate())?.recv().await;
        log::warn!("SIGTERM received. Dump state");
        quit_sx.send(()).await.map_err(|_| anyhow!("send fail"))?;
        Result::<_>::Ok(())
    });

    let mut ip_stack = ipstack::IpStack::new(conf, device);
    loop {
        let ip_stack_stream = tokio::select! {
            k = ip_stack.accept() => k,
            _ = quit.recv() => break,
        }?;
        match ip_stack_stream {
            IpStackStream::Tcp(tcp) => {
                log::trace!("Session count {}", TASK_COUNT.fetch_add(1, Relaxed) + 1);
                let mut k = vdns.write().await;
                if let Some(w) = k.deref_mut() {
                    if let VDNSRES::Addr(dst) = w.process(tcp.peer_addr()) {
                        drop(k);
                        let info = SessionInfo::new(tcp.local_addr(), dst, IpProtocol::Tcp);
                        let proxy_handler = mgr.new_proxy_handler(info.clone(), false).await?;
                        tokio::spawn(async move {
                            if let Err(err) = handle_tcp_session(tcp, server_addr, proxy_handler).await {
                                log::error!("{} error \"{:?}\"", info, err);
                            }
                            log::trace!("Session count {}", TASK_COUNT.fetch_sub(1, Relaxed) - 1);
                        });
                    } else {
                        warn!("Invalid VirtDNS Addr {}", tcp.peer_addr());
                    }
                }
            }
            IpStackStream::Udp(mut udp) => {
                log::trace!("Session count {}", TASK_COUNT.fetch_add(1, Relaxed) + 1);
                let mut k = vdns.write().await;
                if let Some(w) = k.deref_mut() {
                    if let VDNSRES::Addr(dst) = w.process(udp.peer_addr()) {
                        drop(k);
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
                                            log::error!("{} error \"{:?}\"", info, err);
                                        }
                                        log::trace!("Session count {}", TASK_COUNT.fetch_sub(1, Relaxed) - 1);
                                    });
                                    continue;
                                }
                                ArgDns::Handled => {
                                    let vdns = vdns.clone();
                                    tokio::spawn(async move {
                                        let mut pack = BytesMut::with_capacity(128);
                                        while udp.read_buf(&mut pack).await? > 0 {
                                            let k = {
                                                let mut vdns = vdns.write().await;
                                                if let Some(vdns) = vdns.deref_mut() {
                                                    vdns.receive_query(&pack)?
                                                } else {
                                                    exit(0)
                                                }
                                            };
                                            udp.write_all(&k).await?;
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
                                log::error!("{} error \"{:?}\"", info, err);
                                println!("{}", err);
                            }
                            log::trace!("Session count {}", TASK_COUNT.fetch_sub(1, Relaxed) - 1);
                        });
                    } else {
                        warn!("Invalid VirtDNS Addr {}", udp.peer_addr());
                    }
                }
            }
        }
    }
    if let Some(ref pa) = args.state {
        let dump = vd2.write().await.take().unwrap().to_state();
        let by = bincode::serialize(&dump)?;
        tokio::fs::write(pa, &by).await?;
        log::info!("State dumped");
    }

    Ok(())
}

async fn handle_tcp_session(
    tcp_stack: IpStackTcpStream,
    server_addr: SocketAddr,
    proxy_handler: Arc<Mutex<dyn ProxyHandler>>,
) -> crate::Result<()> {
    let mut server = TcpStream::connect(server_addr).await?;
    let session_info = proxy_handler.lock().await.get_session_info();
    log::info!("Beginning {}", session_info);

    let _ = handle_proxy_session(&mut server, proxy_handler).await?;

    let (mut t_rx, mut t_tx) = tokio::io::split(tcp_stack);
    let (mut s_rx, mut s_tx) = tokio::io::split(server);

    let res = tokio::try_join!(
        async {
            let k = tokio::io::copy(&mut t_rx, &mut s_tx).await?;
            anyhow::Ok(k)
        },
        async {
            let k = tokio::io::copy(&mut s_rx, &mut t_tx).await?;
            anyhow::Ok(k)
        }
    );

    log::info!("Ending {} with {:?}", session_info, res);

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
    log::info!("Beginning {}", session_info);

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

    log::info!("Ending {}", session_info);

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
    log::info!("Beginning {}", session_info);

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
                    log::trace!("DNS over TCP query result: {} -> {:?}", name, ip);

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

    log::info!("Ending {}", session_info);

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
            bail!("server closed accidentially")
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
