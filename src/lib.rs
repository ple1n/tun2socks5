#![feature(let_chains)]
#![feature(decl_macro)]

use crate::{
    directions::{IncomingDataEvent, IncomingDirection, OutgoingDirection},
    dns::{DNSState, TUNResponse, VirtDNSHandle, VDNSRES},
    http::HttpManager,
    session_info::{IpProtocol, SessionInfo},
};
use anyhow::{anyhow, bail};
use bytes::BytesMut;
pub use flume;
use futures::{
    channel::{mpsc, oneshot},
    future::pending,
    SinkExt, StreamExt,
};
use id_alloc::NetRange;
use ipstack::{
    stream::{tcp::TcpConfig, IpStackStream, IpStackTcpStream, IpStackUdpStream},
    IpStackConfig, TUNDev,
};
use nsproxy_common::{forever, rpc::FromClient};
use proxy_handler::{ConnectionManager, ProxyHandler};
use socks::SocksProxyManager;
use socks5_impl::protocol::{WireAddress, UserKey};
use std::{
    collections::{HashMap, VecDeque},
    fmt::Debug,
    future::Future,
    io::Write,
    net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4},
    ops::{DerefMut, RangeInclusive},
    path::PathBuf,
    process::exit,
    sync::Arc,
    time::Duration,
};
use tokio::{
    io::{copy_bidirectional, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf},
    net::{TcpSocket, TcpStream},
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
pub use diag;
use diag::{ConnRoute, DiagEvent, DiagServer, StreamKind, Timestamp, next_conn_id};
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

/// Compare this to active number of connected sites by domain name
/// Unlikely to exceed this number.
/// Otherwise, fork opool and use SeqQueue which is unbounded.
const POOL_SIZE: usize = 65535;

pub struct VirtDNSChange {
    pub domain: String,
    pub target: TUNResponse,
}

#[derive(Clone)]
pub struct ProxyInst {
    mgr: Arc<dyn ConnectionManager>,
    server_addr: SocketAddr,
    key: Option<UserKey>,
}

pub async fn main_entry(
    device: TUNDev,
    mtu: u16,
    packet_info: bool,
    args: IArgs,
    mut dns_sx: mpsc::Sender<Option<VirtDNSHandle>>,
    st_sx: flume::Sender<(PathBuf, IpStackTcpStream)>,
) -> crate::Result<()> {
    // Start diag server if socket path is configured
    let diag = if let Some(ref sock_path) = args.diag_sock {
        match DiagServer::start(sock_path.as_path()).await {
            Ok(srv) => { info!("diag server started at {:?}", sock_path); srv }
            Err(e) => { warn!("diag server failed to start: {}, continuing without", e); DiagServer::noop() }
        }
    } else {
        DiagServer::noop()
    };
    use dns::VirtDNSAsync as VirtDNS;

    let dns_addr = args.dns_addr;
    let ipv6_enabled = args.ipv6_enabled;
    let mut vdns = VirtDNS::default(POOL_SIZE)?;
    if let Some(fp) = args.designated {
        info!("load user-designated name mappings from {:?}", &fp);
        let mut f = tokio::fs::File::open(fp).await?;
        let mut buf = String::new();
        f.read_to_string(&mut buf).await?;
        let desig: bimap::BiHashMap<Ipv4Addr, String> = serde_json::from_str(&buf)?;

        todo!()
    }
    use socks5_impl::protocol::Version::{V4, V5};
    let mgr = if let Some(argproxy) = args.proxy {
        let server_addr = argproxy.addr;
        let key = argproxy.credentials.clone();
        let key1 = key.clone();
        Some(ProxyInst {
            mgr: match argproxy.proxy_type {
                ProxyType::Socks5 => Arc::new(SocksProxyManager::new(server_addr, V5, key)) as Arc<dyn ConnectionManager>,
                ProxyType::Socks4 => Arc::new(SocksProxyManager::new(server_addr, V4, key)) as Arc<dyn ConnectionManager>,
                ProxyType::Http => Arc::new(HttpManager::new(server_addr, key)) as Arc<dyn ConnectionManager>,
            },
            server_addr,
            key: key1,
        })
    } else {
        warn!("proxy not supplied. traffic will be sent directly by TUN process");
        None
    };
    let conf = IpStackConfig {
        mtu,
        packet_information: packet_info,
        udp_timeout: Duration::from_secs(20),
        tcp_config: Arc::new(TcpConfig::default()),
    };

    let vh = vdns.handle.clone();
    dns_sx.send(Some(vh.clone())).await;

    use nsproxy_common::rpc::*;

    let mut ip_stack = ipstack::IpStack::new(conf, device);

    loop {
        let wait_id = next_conn_id();
        diag.emit(DiagEvent::Wait {
            id: wait_id,
            ts: Timestamp::now(),
        });
        let ip_stack_stream = ip_stack.accept().await?;
        diag.emit(DiagEvent::WaitEnded {
            id: wait_id,
            ts: Timestamp::now(),
        });
        let body_start = Instant::now();
        let stream_sx = st_sx.clone();
        let iter_conn_id;
        match ip_stack_stream {
            IpStackStream::Tcp(tcp) => {
                let conn_id = next_conn_id();
                iter_conn_id = conn_id;
                diag.emit(DiagEvent::Accept {
                    id: conn_id,
                    ts: Timestamp::now(),
                    kind: StreamKind::Tcp,
                    src: tcp.local_addr().to_string(),
                    dst: tcp.peer_addr().to_string(),
                });
                let mgr = mgr.clone();
                let vh = vh.clone();
                let diag = diag.clone();
                tokio::spawn(async move {
                    let mut vdrs;
                    let mut to_proxy;
                    if mgr.is_some() {
                        to_proxy = Some(WireAddress::SocketAddress(tcp.peer_addr()));
                        vdrs = vh.process(tcp.peer_addr());
                        match &vdrs {
                            VDNSRES::ERR => {
                                warn!("Invalid VirtDNS Addr {}", tcp.peer_addr());
                            }
                            VDNSRES::SpecialHandling(dst) => {
                                to_proxy = match dst {
                                    TUNResponse::ProxiedHost(host) => Some(WireAddress::DomainAddress(host.clone(), tcp.peer_addr().port())),
                                    _ => None,
                                };
                            }
                            VDNSRES::NormalProxying => to_proxy = Some(WireAddress::SocketAddress(tcp.peer_addr())),
                        }
                    } else {
                        vdrs = VDNSRES::SpecialHandling(TUNResponse::Direct(tcp.peer_addr()));
                        to_proxy = None;
                    }

                    if let Some(dst) = to_proxy {
                        let info = SessionInfo::new(tcp.local_addr(), dst, IpProtocol::Tcp);
                        diag.emit(DiagEvent::Route {
                            id: conn_id,
                            ts: Timestamp::now(),
                            route: ConnRoute::Proxied { dest: format!("{}", info) },
                        });
                        if let Some(ProxyInst { mgr, server_addr, key }) = mgr.clone() {
                            let proxy_handler = mgr.new_proxy_handler(info.clone(), false).await?;
                            diag.emit(DiagEvent::Connected { id: conn_id, ts: Timestamp::now() });
                            if let Err(err) = handle_tcp_session(tcp, server_addr, proxy_handler).await {
                                // This kind of error causes mid-connection drop.
                                // An error in TCP is handled by state transition internally.
                                diag.emit(DiagEvent::Finished {
                                    id: conn_id, ts: Timestamp::now(),
                                    error: Some(format!("{:?}", err)),
                                    bytes_up: 0, bytes_down: 0,
                                });
                                error!("Conn dropped {} {:?}", info, err);
                            } else {
                                diag.emit(DiagEvent::Finished {
                                    id: conn_id, ts: Timestamp::now(),
                                    error: None, bytes_up: 0, bytes_down: 0,
                                });
                            }
                        }
                    } else {
                        match vdrs {
                            VDNSRES::SpecialHandling(dst) => match dst {
                                TUNResponse::NATByTUN(sock) => {
                                    diag.emit(DiagEvent::Route {
                                        id: conn_id, ts: Timestamp::now(),
                                        route: ConnRoute::Nat { dest: sock.to_string() },
                                    });
                                    if let Err(err) = handle_tcp_nat(tcp, sock).await {
                                        diag.emit(DiagEvent::Finished {
                                            id: conn_id, ts: Timestamp::now(),
                                            error: Some(format!("{}", err)),
                                            bytes_up: 0, bytes_down: 0,
                                        });
                                        info!("tcp drop {} {}", sock, err);
                                    }
                                }
                                TUNResponse::Direct(sock) => {
                                    diag.emit(DiagEvent::Route {
                                        id: conn_id, ts: Timestamp::now(),
                                        route: ConnRoute::Direct { dest: sock.to_string() },
                                    });
                                    if let Err(err) = handle_tcp_nat(tcp, sock).await {
                                        diag.emit(DiagEvent::Finished {
                                            id: conn_id, ts: Timestamp::now(),
                                            error: Some(format!("{}", err)),
                                            bytes_up: 0, bytes_down: 0,
                                        });
                                        info!("tcp drop {} {}", sock, err);
                                    }
                                }
                                TUNResponse::Files(root) => {
                                    diag.emit(DiagEvent::Route {
                                        id: conn_id, ts: Timestamp::now(),
                                        route: ConnRoute::FileServe { root: root.to_string_lossy().to_string() },
                                    });
                                    info!("tun: serve files at {:?}", root);
                                    let k = stream_sx.send_async((root, tcp)).await;
                                    if k.is_err() {
                                        warn!("{:?}", k);
                                    }
                                }
                                _ => {
                                    warn!("unexpected traffic, indicating misconfigured routing")
                                }
                            },
                            _ => {}
                        }
                    }

                    anyhow::Ok(())
                });
            }
            IpStackStream::Udp(mut udp) => {
                let conn_id = next_conn_id();
                iter_conn_id = conn_id;
                diag.emit(DiagEvent::Accept {
                    id: conn_id,
                    ts: Timestamp::now(),
                    kind: StreamKind::Udp,
                    src: udp.local_addr().to_string(),
                    dst: udp.peer_addr().to_string(),
                });
                let mut resolv;
                let mut to_proxy;
                let peeraddr = udp.peer_addr();

                if mgr.is_none() {
                    to_proxy = None;
                    resolv = VDNSRES::SpecialHandling(TUNResponse::Direct(peeraddr))
                } else {
                    resolv = vh.process(udp.peer_addr());
                    to_proxy = match &resolv {
                        VDNSRES::NormalProxying => Some(WireAddress::SocketAddress(udp.peer_addr())),
                        VDNSRES::SpecialHandling(TUNResponse::ProxiedHost(host)) => {
                            Some(WireAddress::DomainAddress(host.to_owned(), udp.peer_addr().port()))
                        }
                        _ => None,
                    };
                }

                if let Some(dst) = to_proxy {
                    let port = dst.port();
                    let info = SessionInfo::new(udp.local_addr(), dst, IpProtocol::Udp);
                    if port == DNS_PORT && matches!(args.dns, ArgDns::OverTcp) {
                        if let Some(ProxyInst { mgr, server_addr, key }) = mgr.clone() {
                            let proxy_handler = mgr.new_proxy_handler(info.clone(), false).await?;
                            tokio::spawn(async move {
                                if let Err(err) = handle_dns_over_tcp_session(udp, server_addr, proxy_handler, ipv6_enabled).await {
                                    error!("{} error \"{:?}\"", info, err);
                                }
                            });
                        }
                    } else if port == DNS_PORT && matches!(args.dns, ArgDns::Handled) {
                        let vh = vh.clone();
                        let diag = diag.clone();
                        tokio::spawn(async move {
                            let vh = vh;
                            let mut pack = BytesMut::with_capacity(256);
                            while udp.read_buf(&mut pack).await? > 0 {
                                let query = match dns::parse_data_to_dns_message(&pack, false)
                                    .and_then(|m| dns::extract_domain_from_dns_message(&m))
                                {
                                    Ok(q) => {
                                        diag.emit(DiagEvent::DnsQuery {
                                            id: conn_id,
                                            ts: Timestamp::now(),
                                            query: q.clone(),
                                        });
                                        Some(q)
                                    }
                                    Err(e) => {
                                        warn!("udp:dns query parse error: {}", e);
                                        None
                                    }
                                };

                                let k = vh.receive_query(&pack);
                                if let Ok(resp) = k {
                                    if let Some(q) = query.clone() {
                                        let result = match dns::parse_data_to_dns_message(&resp, false)
                                            .and_then(|m| dns::extract_ipaddr_from_dns_message(&m))
                                        {
                                            Ok(ip) => ip.to_string(),
                                            Err(e) => format!("err: {}", e),
                                        };
                                        diag.emit(DiagEvent::DnsResolved {
                                            id: conn_id,
                                            ts: Timestamp::now(),
                                            domain: q,
                                            result,
                                        });
                                    }
                                    udp.write_all(&resp).await?;
                                } else {
                                    let err = k.err().unwrap();
                                    let domain = query.unwrap_or_else(|| "<parse-error>".to_string());
                                    diag.emit(DiagEvent::DnsResolved {
                                        id: conn_id,
                                        ts: Timestamp::now(),
                                        domain,
                                        result: format!("err: {}", err),
                                    });
                                    error!("udp:dns error decoding {:?}", err);
                                }
                                pack.clear();
                            }
                            crate::Result::<()>::Ok(())
                        });
                    } else {
                        if let Some(ProxyInst { mgr, server_addr, key }) = mgr.clone() {
                            let proxy_handler = mgr.new_proxy_handler(info.clone(), true).await?;
                            tokio::spawn(async move {
                                if let Err(err) = handle_udp_associate_session(udp, server_addr, proxy_handler, ipv6_enabled).await {
                                    error!("{} error \"{:?}\"", info, err);
                                }
                            });
                        }
                    }
                } else {
                    match resolv {
                        VDNSRES::SpecialHandling(TUNResponse::NATByTUN(host)) | VDNSRES::SpecialHandling(TUNResponse::Direct(host)) => {
                            info!("UDP protocol: NAT to {}. {:?}", &host, resolv);
                            tokio::spawn(async move {
                                handle_udp_nat(udp, host).await?;
                                aok!(())
                            });
                        }
                        VDNSRES::SpecialHandling(TUNResponse::Files(root)) => {}
                        _ => {
                            warn!("Invalid VirtDNS Addr {}", peeraddr);
                        }
                    }
                }
            }
        }
        diag.emit(DiagEvent::Dispatched {
            id: iter_conn_id,
            dispatch_us: body_start.elapsed().as_micros() as u64,
        });
    }

    Ok(())
}

async fn handle_tcp_nat(mut tcp_stack: IpStackTcpStream, server_addr: SocketAddr) -> crate::Result<()> {
    info!("NAT {} (app) connect {} (remote)", tcp_stack.local_addr(), &server_addr);
    let mut server = TcpStream::connect(server_addr).await?;

    tokio::io::copy_bidirectional(&mut tcp_stack, &mut server).await?;

    Ok(())
}

async fn handle_tcp_session(
    mut tcp_stack: IpStackTcpStream,
    server_addr: SocketAddr,
    proxy_handler: Arc<Mutex<dyn ProxyHandler>>,
) -> crate::Result<()> {
    let mut server = TcpStream::connect(server_addr).await
        .map_err(|e| anyhow!("proxy server connection refused at {}: {}", server_addr, e))?;
    // let session_info = proxy_handler.lock().await.get_session_info();
    // debug!("beginning {}", session_info);

    let _ = handle_proxy_session(&mut server, proxy_handler).await?;

    let (mut t_rx, mut t_tx) = tokio::io::split(tcp_stack);
    let (mut s_rx, mut s_tx) = tokio::io::split(server);

    let res = tokio::try_join!(
        async {
            let k = tokio::io::copy(&mut t_rx, &mut s_tx).await
                .map_err(|e| anyhow!("user side closed: {}", e));
            let _ = s_tx.shutdown().await;
            k
        },
        async {
            let k = tokio::io::copy(&mut s_rx, &mut t_tx).await
                .map_err(|e| anyhow!("proxy side closed: {}", e));
            let _ = t_tx.shutdown().await;
            k
        }
    );
    let (up, down) = res?;
    debug!("tcp session done: {} bytes up, {} bytes down", up, down);

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
    let mut server = TcpStream::connect(server_addr).await
        .map_err(|e| anyhow!("proxy server connection refused at {}: {}", server_addr, e))?;
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

async fn handle_udp_nat(mut udp_stack: IpStackUdpStream, server_addr: SocketAddr) -> crate::Result<()> {
    let mut udp_server = UdpStream::connect(server_addr).await?;
    debug!("UDP connected to {}", server_addr);
    copy_bidirectional(&mut udp_server, &mut udp_stack).await?;

    Ok(())
}

async fn handle_dns_over_tcp_session(
    mut udp_stack: IpStackUdpStream,
    server_addr: SocketAddr,
    proxy_handler: Arc<Mutex<dyn ProxyHandler>>,
    ipv6_enabled: bool,
) -> crate::Result<()> {
    let mut server = TcpStream::connect(server_addr).await
        .map_err(|e| anyhow!("proxy server connection refused at {}: {}", server_addr, e))?;
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
