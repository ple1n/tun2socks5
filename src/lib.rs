#![feature(let_chains)]
#![feature(decl_macro)]

use crate::{
    directions::{IncomingDataEvent, IncomingDirection, OutgoingDirection},
    dns::{DNSState, VirtDNSHandle},
    http::HttpManager,
    session_info::{IpProtocol, SessionInfo},
};
use anyhow::{anyhow, bail};
use bytes::BytesMut;
pub use diag;
use diag::{next_conn_id, ConnId, DiagEvent, DiagServer, StreamKind, Timestamp};
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
use nsproxy_common::{
    routing::{DropReason, RoutingDecision, RoutingResovled, VDNSRES},
    stats::{HostRouteKey, HostRouteMetric, HostRouteStats, ObservedRoute, TransferRateSample, TransferRateTracker},
};
use proxy_handler::{ConnectionManager, ProxyHandler};
use socks::SocksProxyManager;
use socks5_impl::protocol::{UserKey, WireAddress};
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
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf},
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
pub use {
    args::*,
    error::{Error, Result},
};

mod args;
pub mod directions;
pub mod dns;
pub mod error;
pub mod http;
mod private_ip;
pub mod proxy_handler;
pub mod session_info;
pub mod socks;
pub mod udp_associate;

pub use ipstack;
pub use tun_rs;

const DNS_PORT: u16 = 53;
const MAX_HOST_ROUTE_STATS: usize = 16_384;

type HostRouteStatsMap = Arc<Mutex<HashMap<HostRouteKey, HostRouteStats>>>;

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
    pub target: RoutingDecision,
}

#[derive(Clone)]
pub struct ProxyInst {
    mgr: Arc<dyn ConnectionManager>,
    server_addr: SocketAddr,
    key: Option<UserKey>,
    shared_udp: Option<Arc<udp_associate::SharedUdpAssociate>>,
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
    let (diag, diag_commands) = if let Some(ref sock_path) = args.diag_sock {
        match DiagServer::start(sock_path.as_path(), diag::DEFAULT_CONN_PERSIST).await {
            Ok((srv, cmd_rx)) => {
                info!("diag server started at {:?}", sock_path);
                (srv, Some(cmd_rx))
            }
            Err(e) => {
                warn!("diag server failed to start: {}, continuing without", e);
                (DiagServer::noop(), None)
            }
        }
    } else {
        (DiagServer::noop(), None)
    };
    let host_route_stats: HostRouteStatsMap = Arc::new(Mutex::new(HashMap::new()));
    if let Some(mut commands) = diag_commands {
        let diag = diag.clone();
        let host_route_stats = host_route_stats.clone();
        tokio::spawn(async move {
            while let Some(command) = commands.recv().await {
                match command {
                    diag::ControlCommand::QueryHostRouteStats => {
                        let ts = Timestamp::now();
                        let mut stats = {
                            let host_route_stats = host_route_stats.lock().await;
                            host_route_stats
                                .iter()
                                .map(|(key, value)| value.metric(key.clone(), ts))
                                .collect::<Vec<_>>()
                        };
                        stats.sort_by_key(|metric| metric.key.clone());
                        diag.emit(DiagEvent::HostRouteStatsSnapshot { ts, stats });
                    }
                    command => warn!(
                        command = ?command,
                        "unsupported diagnostic command in TUN NAT mode"
                    ),
                }
            }
        });
    }
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
        let shared_udp = if matches!(argproxy.proxy_type, ProxyType::Socks5) {
            Some(udp_associate::SharedUdpAssociate::new(server_addr, key.clone(), diag.clone()))
        } else {
            None
        };
        Some(ProxyInst {
            mgr: match argproxy.proxy_type {
                ProxyType::Socks5 => Arc::new(SocksProxyManager::new(server_addr, V5, key)) as Arc<dyn ConnectionManager>,
                ProxyType::Socks4 => Arc::new(SocksProxyManager::new(server_addr, V4, key)) as Arc<dyn ConnectionManager>,
                ProxyType::Http => Arc::new(HttpManager::new(server_addr, key)) as Arc<dyn ConnectionManager>,
            },
            server_addr,
            key: key1,
            shared_udp,
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
        let host_route_stats = host_route_stats.clone();
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
                        vdrs = vh.preprocess(tcp.peer_addr());
                        match &vdrs {
                            VDNSRES::ERR => {
                                warn!("Invalid VirtDNS Addr {}", tcp.peer_addr());
                            }
                            VDNSRES::Opine(dst) => {
                                to_proxy = match dst {
                                    RoutingDecision::HostOverProxy(host) => {
                                        Some(WireAddress::DomainAddress(host.clone(), tcp.peer_addr().port()))
                                    }
                                    _ => None,
                                };
                            }
                            VDNSRES::NormalProxying => to_proxy = Some(WireAddress::SocketAddress(tcp.peer_addr())),
                        }
                    } else {
                        vdrs = VDNSRES::Opine(RoutingDecision::NoProxy(tcp.peer_addr()));
                        to_proxy = None;
                    }

                    if let Some(dst) = to_proxy {
                        diag.emit(DiagEvent::Route {
                            id: conn_id,
                            ts: Timestamp::now(),
                            route: RoutingResovled::ProxyResovled {
                                target: dst.clone(),
                                id: nsproxy_common::routing::ProxyID::for_remote(tcp.peer_addr()),
                            },
                        });
                        let info = SessionInfo::new(tcp.local_addr(), dst, IpProtocol::Tcp);
                        if let Some(ProxyInst { mgr, server_addr, .. }) = mgr.clone() {
                            let proxy_handler = mgr.new_proxy_handler(info.clone(), false).await?;
                            diag.emit(DiagEvent::Connected {
                                id: conn_id,
                                ts: Timestamp::now(),
                            });
                            if let Err(err) = handle_tcp_session(tcp, server_addr, proxy_handler).await {
                                // This kind of error causes mid-connection drop.
                                // An error in TCP is handled by state transition internally.
                                diag.emit(DiagEvent::Finished {
                                    id: conn_id,
                                    ts: Timestamp::now(),
                                    error: Some(format!("{:?}", err)),
                                    bytes_up: 0.0,
                                    bytes_down: 0.0,
                                });
                                error!("Conn dropped {} {:?}", info, err);
                            } else {
                                diag.emit(DiagEvent::Finished {
                                    id: conn_id,
                                    ts: Timestamp::now(),
                                    error: None,
                                    bytes_up: 0.0,
                                    bytes_down: 0.0,
                                });
                            }
                        }
                    } else {
                        match vdrs {
                            VDNSRES::Opine(dst) => match dst {
                                dst @ RoutingDecision::NATByTUN(sock) | dst @ RoutingDecision::NoProxy(sock) => {
                                    let route = match dst {
                                        RoutingDecision::NATByTUN(_) => RoutingResovled::NATByTUN(sock),
                                        RoutingDecision::NoProxy(_) => RoutingResovled::NoProxy(sock),
                                        _ => unreachable!(),
                                    };
                                    diag.emit(DiagEvent::Route {
                                        id: conn_id,
                                        ts: Timestamp::now(),
                                        route,
                                    });
                                    match handle_tcp_nat(tcp, sock, diag.clone(), conn_id, host_route_stats).await {
                                        Ok((bytes_up, bytes_down)) => {
                                            diag.emit(DiagEvent::Finished {
                                                id: conn_id,
                                                ts: Timestamp::now(),
                                                error: None,
                                                bytes_up: bytes_up as f32,
                                                bytes_down: bytes_down as f32,
                                            });
                                        }
                                        Err(err) => {
                                            diag.emit(DiagEvent::Finished {
                                                id: conn_id,
                                                ts: Timestamp::now(),
                                                error: Some(err.to_string()),
                                                bytes_up: 0.0,
                                                bytes_down: 0.0,
                                            });
                                            info!("tcp drop {} {}", sock, err);
                                        }
                                    }
                                }
                                RoutingDecision::File(root) => {
                                    diag.emit(DiagEvent::Route {
                                        id: conn_id,
                                        ts: Timestamp::now(),
                                        route: RoutingResovled::ProxyResovled {
                                            target: socks5_impl::protocol::WireAddress::SocketAddress(tcp.peer_addr()),
                                            id: nsproxy_common::routing::ProxyID::for_file(root.as_path()),
                                        },
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
                    resolv = VDNSRES::Opine(RoutingDecision::NoProxy(peeraddr))
                } else {
                    resolv = vh.preprocess(udp.peer_addr());
                    to_proxy = match &resolv {
                        VDNSRES::NormalProxying => Some(WireAddress::SocketAddress(udp.peer_addr())),
                        VDNSRES::Opine(RoutingDecision::HostOverProxy(host)) => {
                            Some(WireAddress::DomainAddress(host.to_owned(), udp.peer_addr().port()))
                        }
                        _ => None,
                    };
                }

                if let Some(dst) = to_proxy {
                    let port = dst.port();
                    let info = SessionInfo::new(udp.local_addr(), dst, IpProtocol::Udp);
                    if port == DNS_PORT && matches!(args.dns, ArgDns::OverTcp) {
                        if let Some(ProxyInst { mgr, server_addr, .. }) = mgr.clone() {
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
                        if let Some(ProxyInst {
                            mgr,
                            server_addr,
                            shared_udp,
                            ..
                        }) = mgr.clone()
                        {
                            if let Some(shared_udp) = shared_udp {
                                let diag = diag.clone();
                                tokio::spawn(async move {
                                    if let Err(err) =
                                        handle_shared_udp_session(udp, info.clone(), conn_id, shared_udp, diag, ipv6_enabled).await
                                    {
                                        error!("{} error \"{:?}\"", info, err);
                                    }
                                });
                            } else {
                                let proxy_handler = mgr.new_proxy_handler(info.clone(), true).await?;
                                tokio::spawn(async move {
                                    if let Err(err) = handle_udp_associate_session(udp, server_addr, proxy_handler, ipv6_enabled).await {
                                        error!("{} error \"{:?}\"", info, err);
                                    }
                                });
                            }
                        }
                    }
                } else {
                    match resolv {
                        route @ VDNSRES::Opine(RoutingDecision::NATByTUN(host))
                        | route @ VDNSRES::Opine(RoutingDecision::NoProxy(host)) => {
                            info!("UDP protocol: NAT to {}", &host);
                            let route = match route {
                                VDNSRES::Opine(RoutingDecision::NATByTUN(_)) => RoutingResovled::NATByTUN(host),
                                VDNSRES::Opine(RoutingDecision::NoProxy(_)) => RoutingResovled::NoProxy(host),
                                _ => unreachable!(),
                            };
                            diag.emit(DiagEvent::Route {
                                id: conn_id,
                                ts: Timestamp::now(),
                                route,
                            });
                            record_host_route_observed(&host_route_stats, &diag, WireAddress::SocketAddress(host), ObservedRoute::NoProxy)
                                .await;
                            let host_route_stats = host_route_stats.clone();
                            let diag = diag.clone();
                            tokio::spawn(async move {
                                match handle_udp_nat(udp, host, diag.clone(), conn_id, host_route_stats).await {
                                    Ok((bytes_up, bytes_down)) => {
                                        diag.emit(DiagEvent::Finished {
                                            id: conn_id,
                                            ts: Timestamp::now(),
                                            error: None,
                                            bytes_up: bytes_up as f32,
                                            bytes_down: bytes_down as f32,
                                        });
                                    }
                                    Err(err) => {
                                        diag.emit(DiagEvent::Finished {
                                            id: conn_id,
                                            ts: Timestamp::now(),
                                            error: Some(err.to_string()),
                                            bytes_up: 0.0,
                                            bytes_down: 0.0,
                                        });
                                        error!("UDP NAT to {} failed: {}", host, err);
                                    }
                                }
                                aok!(())
                            });
                        }
                        VDNSRES::Opine(RoutingDecision::File(_root)) => {}
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

async fn handle_tcp_nat(
    mut tcp_stack: IpStackTcpStream,
    server_addr: SocketAddr,
    diag: DiagServer,
    conn_id: ConnId,
    host_route_stats: HostRouteStatsMap,
) -> crate::Result<(u64, u64)> {
    info!("NAT {} (app) connect {} (remote)", tcp_stack.local_addr(), &server_addr);
    let connect_start = Instant::now();
    let mut server = match TcpStream::connect(server_addr).await {
        Ok(server) => server,
        Err(error) => {
            record_no_proxy_attempt(
                &host_route_stats,
                &diag,
                WireAddress::SocketAddress(server_addr),
                connect_start.elapsed(),
                false,
            )
            .await;
            return Err(error.into());
        }
    };
    let connect_latency = connect_start.elapsed();
    diag.emit(DiagEvent::Connected {
        id: conn_id,
        ts: Timestamp::now(),
    });

    match copy_bidirectional_with_stats(
        &mut tcp_stack,
        &mut server,
        host_route_stats.clone(),
        diag.clone(),
        WireAddress::SocketAddress(server_addr),
        false,
    )
    .await
    {
        Ok((bytes_up, bytes_down, upload_sample, download_sample)) => {
            update_no_proxy_stats(&host_route_stats, &diag, WireAddress::SocketAddress(server_addr), |stats, at| {
                stats.record_tcp_connection(connect_latency, upload_sample, download_sample, at);
            })
            .await;
            Ok((bytes_up, bytes_down))
        }
        Err(error) => {
            record_no_proxy_attempt(
                &host_route_stats,
                &diag,
                WireAddress::SocketAddress(server_addr),
                connect_latency,
                false,
            )
            .await;
            Err(error)
        }
    }
}

async fn handle_udp_nat(
    mut udp_stack: IpStackUdpStream,
    server_addr: SocketAddr,
    diag: DiagServer,
    conn_id: ConnId,
    host_route_stats: HostRouteStatsMap,
) -> crate::Result<(u64, u64)> {
    let mut udp_server = UdpStream::connect(server_addr).await?;
    debug!("UDP connected to {}", server_addr);
    diag.emit(DiagEvent::Connected {
        id: conn_id,
        ts: Timestamp::now(),
    });
    let (bytes_up, bytes_down, _, _) = copy_bidirectional_with_stats(
        &mut udp_stack,
        &mut udp_server,
        host_route_stats,
        diag,
        WireAddress::SocketAddress(server_addr),
        true,
    )
    .await?;
    Ok((bytes_up, bytes_down))
}

async fn update_no_proxy_stats(
    host_route_stats: &HostRouteStatsMap,
    diag: &DiagServer,
    target: WireAddress,
    update: impl FnOnce(&mut HostRouteStats, Timestamp),
) {
    let key = HostRouteKey::new(target, ObservedRoute::NoProxy);
    let observed_at = Timestamp::now();
    let metric = {
        let mut stats = host_route_stats.lock().await;
        let entry = host_route_stats_mut(&mut stats, key.clone());
        update(entry, observed_at);
        entry.metric(key, observed_at)
    };
    diag.emit(DiagEvent::HostRouteStatsUpdated {
        ts: metric.observed_at,
        stat: metric,
    });
}

fn host_route_stats_mut(stats: &mut HashMap<HostRouteKey, HostRouteStats>, key: HostRouteKey) -> &mut HostRouteStats {
    if !stats.contains_key(&key) && stats.len() >= MAX_HOST_ROUTE_STATS {
        if let Some(oldest) = stats
            .iter()
            .min_by_key(|(_, stats)| stats.last_observed)
            .map(|(key, _)| key.clone())
        {
            stats.remove(&oldest);
        }
    }
    stats.entry(key).or_default()
}

async fn record_no_proxy_attempt(
    host_route_stats: &HostRouteStatsMap,
    diag: &DiagServer,
    target: WireAddress,
    connect_latency: Duration,
    success: bool,
) {
    update_no_proxy_stats(host_route_stats, diag, target, |stats, at| {
        stats.record_tcp_attempt(connect_latency, success, at);
    })
    .await;
}

async fn record_host_route_observed(host_route_stats: &HostRouteStatsMap, diag: &DiagServer, target: WireAddress, route: ObservedRoute) {
    let key = HostRouteKey::new(target, route);
    let observed_at = Timestamp::now();
    let metric = {
        let mut stats = host_route_stats.lock().await;
        let entry = host_route_stats_mut(&mut stats, key.clone());
        entry.last_observed = Some(observed_at);
        entry.metric(key, observed_at)
    };
    diag.emit(DiagEvent::HostRouteStatsUpdated {
        ts: metric.observed_at,
        stat: metric,
    });
}

async fn record_no_proxy_transfer_samples(
    host_route_stats: &HostRouteStatsMap,
    diag: &DiagServer,
    target: WireAddress,
    upload_sample: Option<TransferRateSample>,
    download_sample: Option<TransferRateSample>,
    udp: bool,
) {
    if upload_sample.is_none() && download_sample.is_none() {
        return;
    }

    update_no_proxy_stats(host_route_stats, diag, target, |stats, at| {
        if udp {
            stats.record_udp_transfer_samples(upload_sample, download_sample, at);
        } else {
            stats.record_tcp_transfer_samples(upload_sample, download_sample, at);
        }
    })
    .await;
}

async fn copy_bidirectional_with_stats<A, B>(
    left: &mut A,
    right: &mut B,
    host_route_stats: HostRouteStatsMap,
    diag: DiagServer,
    stats_target: WireAddress,
    udp: bool,
) -> crate::Result<(u64, u64, Option<TransferRateSample>, Option<TransferRateSample>)>
where
    A: AsyncRead + AsyncWrite + Unpin + ?Sized,
    B: AsyncRead + AsyncWrite + Unpin + ?Sized,
{
    let (mut left_read, mut left_write) = tokio::io::split(left);
    let (mut right_read, mut right_write) = tokio::io::split(right);
    let transfer_start = Instant::now();

    let upload = copy_direction_with_stats(
        &mut left_read,
        &mut right_write,
        transfer_start,
        host_route_stats.clone(),
        diag.clone(),
        stats_target.clone(),
        udp,
        true,
    );
    let download = copy_direction_with_stats(
        &mut right_read,
        &mut left_write,
        transfer_start,
        host_route_stats,
        diag,
        stats_target,
        udp,
        false,
    );
    let ((bytes_up, upload_sample), (bytes_down, download_sample)) = tokio::try_join!(upload, download)?;
    Ok((bytes_up, bytes_down, upload_sample, download_sample))
}

#[allow(clippy::too_many_arguments)]
async fn copy_direction_with_stats<R, W>(
    reader: &mut R,
    writer: &mut W,
    transfer_start: Instant,
    host_route_stats: HostRouteStatsMap,
    diag: DiagServer,
    stats_target: WireAddress,
    udp: bool,
    upload: bool,
) -> crate::Result<(u64, Option<TransferRateSample>)>
where
    R: AsyncRead + Unpin + ?Sized,
    W: AsyncWrite + Unpin + ?Sized,
{
    let mut buffer = [0u8; 8192];
    let mut bytes_copied = 0u64;
    let mut rate_tracker = TransferRateTracker::default();
    let mut last_rate_update = Duration::ZERO;

    loop {
        let read = reader.read(&mut buffer).await?;
        if read == 0 {
            break;
        }

        let mut written = 0;
        while written < read {
            let count = writer.write(&buffer[written..read]).await?;
            if count == 0 {
                return Err(std::io::Error::from(std::io::ErrorKind::WriteZero).into());
            }
            written += count;
            bytes_copied = bytes_copied.saturating_add(count as u64);
            let elapsed = transfer_start.elapsed();
            rate_tracker.record(count as u128, elapsed);

            if elapsed.saturating_sub(last_rate_update) >= Duration::from_secs(1) {
                if let Some(sample) = rate_tracker.sample(Timestamp::now(), elapsed) {
                    let (upload_sample, download_sample) = if upload { (Some(sample), None) } else { (None, Some(sample)) };
                    record_no_proxy_transfer_samples(&host_route_stats, &diag, stats_target.clone(), upload_sample, download_sample, udp)
                        .await;
                    last_rate_update = elapsed;
                }
            }
        }
    }

    if let Err(error) = writer.shutdown().await {
        if error.kind() != std::io::ErrorKind::BrokenPipe && error.kind() != std::io::ErrorKind::ConnectionReset {
            return Err(error.into());
        }
    }
    let sample = rate_tracker.sample(Timestamp::now(), transfer_start.elapsed());
    if let Some(sample) = sample {
        let (upload_sample, download_sample) = if upload { (Some(sample), None) } else { (None, Some(sample)) };
        record_no_proxy_transfer_samples(&host_route_stats, &diag, stats_target, upload_sample, download_sample, udp).await;
    }

    Ok((bytes_copied, sample))
}

async fn handle_tcp_session(
    mut tcp_stack: IpStackTcpStream,
    server_addr: SocketAddr,
    proxy_handler: Arc<Mutex<dyn ProxyHandler>>,
) -> crate::Result<()> {
    let mut server = TcpStream::connect(server_addr)
        .await
        .map_err(|e| anyhow!("proxy server connection refused at {}: {}", server_addr, e))?;
    // let session_info = proxy_handler.lock().await.get_session_info();
    // debug!("beginning {}", session_info);

    let _ = handle_proxy_session(&mut server, proxy_handler).await?;

    let (mut t_rx, mut t_tx) = tokio::io::split(tcp_stack);
    let (mut s_rx, mut s_tx) = tokio::io::split(server);

    let res = tokio::try_join!(
        async {
            let k = tokio::io::copy(&mut t_rx, &mut s_tx)
                .await
                .map_err(|e| anyhow!("user side closed: {}", e));
            let _ = s_tx.shutdown().await;
            k
        },
        async {
            let k = tokio::io::copy(&mut s_rx, &mut t_tx)
                .await
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
    let mut server = TcpStream::connect(server_addr)
        .await
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

                let (source_addr, data) = parse_socks5_udp_datagram(buf2)?;

                let buf = if session_info.dst.port() == DNS_PORT {
                    let mut message = dns::parse_data_to_dns_message(data, false)?;
                    if !ipv6_enabled {
                        dns::remove_ipv6_entries(&mut message);
                    }
                    message.to_vec()?
                } else {
                    data.to_vec()
                };

                udp_stack.write_datagram_from(source_addr, &buf)?;
            }
        }
    }

    Ok(())
}

async fn handle_shared_udp_session(
    mut udp_stack: IpStackUdpStream,
    session_info: SessionInfo,
    conn_id: ConnId,
    shared_udp: Arc<udp_associate::SharedUdpAssociate>,
    diag: DiagServer,
    ipv6_enabled: bool,
) -> crate::Result<()> {
    diag.emit(DiagEvent::Connected {
        id: conn_id,
        ts: Timestamp::now(),
    });

    let peer_addr = match &session_info.dst {
        WireAddress::SocketAddress(addr) => *addr,
        WireAddress::DomainAddress(_, _) => udp_stack.peer_addr(),
    };

    let mut inbound_rx = shared_udp.register_flow(conn_id, udp_stack.local_addr(), peer_addr).await;

    let mut buf = [0_u8; 4096];
    let mut bytes_up: f32 = 0.0;
    let mut bytes_down: f32 = 0.0;
    let mut session_err: Option<String> = None;

    loop {
        tokio::select! {
            len = udp_stack.read(&mut buf) => {
                let len = match len {
                    Ok(0) => break,
                    Ok(n) => n,
                    Err(e) => {
                        session_err = Some(e.to_string());
                        break;
                    }
                };
                bytes_up += len as f32;
                if let Err(e) = shared_udp.send_datagram(session_info.dst.clone(), &buf[..len]).await {
                    session_err = Some(e.to_string());
                    break;
                }
            }
            Some((remote_source, payload)) = inbound_rx.recv() => {
                bytes_down += payload.len() as f32;
                let data = if session_info.dst.port() == DNS_PORT {
                    let mut message = dns::parse_data_to_dns_message(&payload, false)?;
                    if !ipv6_enabled {
                        dns::remove_ipv6_entries(&mut message);
                    }
                    message.to_vec()?
                } else {
                    payload
                };

                if let Err(e) = udp_stack.write_datagram_from(remote_source, &data) {
                    session_err = Some(e.to_string());
                    break;
                }
            }
        }
    }

    shared_udp.deregister_flow(conn_id).await;
    diag.emit(DiagEvent::Finished {
        id: conn_id,
        ts: Timestamp::now(),
        error: session_err,
        bytes_up,
        bytes_down,
    });

    Ok(())
}

pub(crate) fn parse_socks5_udp_datagram(buf: &[u8]) -> Result<(SocketAddr, &[u8])> {
    use socks5_impl::protocol::{StreamOperation, UdpHeader};

    let header = UdpHeader::retrieve_from_stream(&mut &buf[..])?;
    if header.frag != 0 {
        bail!("fragmented SOCKS5 UDP datagrams are unsupported");
    }
    let source_addr = SocketAddr::try_from(&header.address)?;
    let data = buf.get(header.len()..).ok_or_else(|| anyhow!("truncated SOCKS5 UDP datagram"))?;

    Ok((source_addr, data))
}

#[cfg(test)]
mod udp_associate_tests {
    use super::*;
    use socks5_impl::protocol::{StreamOperation, UdpHeader};

    #[test]
    fn parses_udp_reply_source_address_separately_from_payload() {
        let source_addr: SocketAddr = "203.0.113.7:41844".parse().unwrap();
        let mut datagram = Vec::new();
        UdpHeader::new(0, WireAddress::from(source_addr))
            .write_to_stream(&mut datagram)
            .unwrap();
        datagram.extend_from_slice(b"payload");

        let (parsed_source, payload) = parse_socks5_udp_datagram(&datagram).unwrap();

        assert_eq!(parsed_source, source_addr);
        assert_eq!(payload, b"payload");
    }

    #[test]
    fn rejects_fragmented_udp_replies() {
        let mut datagram = Vec::new();
        UdpHeader::new(1, WireAddress::from("203.0.113.7:41844".parse::<SocketAddr>().unwrap()))
            .write_to_stream(&mut datagram)
            .unwrap();
        datagram.extend_from_slice(b"payload");

        assert!(parse_socks5_udp_datagram(&datagram).is_err());
    }

    #[test]
    fn test_resolve_effective_relay_addresses() {
        use udp_associate::resolve_effective_relay;
        let server_addr: SocketAddr = "192.168.1.100:1080".parse().unwrap();

        // 1. Wildcard IPv4 0.0.0.0 -> resolves to server_addr.ip():port
        let wildcard_v4 = WireAddress::SocketAddress("0.0.0.0:45240".parse().unwrap());
        let eff1 = resolve_effective_relay(&wildcard_v4, server_addr);
        assert_eq!(eff1, "192.168.1.100:45240".parse().unwrap());

        // 2. Concrete public IP -> preserved as-is
        let concrete_v4 = WireAddress::SocketAddress("95.173.199.73:45240".parse().unwrap());
        let eff2 = resolve_effective_relay(&concrete_v4, server_addr);
        assert_eq!(eff2, "95.173.199.73:45240".parse().unwrap());

        // 3. Domain address -> resolves to server_addr.ip():port
        let domain_addr = WireAddress::DomainAddress("proxy.example.com".to_string(), 34567);
        let eff3 = resolve_effective_relay(&domain_addr, server_addr);
        assert_eq!(eff3, "192.168.1.100:34567".parse().unwrap());
    }

    #[tokio::test]
    async fn test_shared_udp_flow_registration_and_demux() {
        let server_addr: SocketAddr = "127.0.0.1:1080".parse().unwrap();
        let diag = DiagServer::noop();
        let shared = udp_associate::SharedUdpAssociate::new(server_addr, None, diag);

        let local_addr: SocketAddr = "198.18.0.1:51257".parse().unwrap();
        let peer_addr: SocketAddr = "23.234.105.208:54468".parse().unwrap();
        let conn_id = ConnId(42);

        let mut rx = shared.register_flow(conn_id, local_addr, peer_addr).await;

        // Build a mock SOCKS5 datagram arriving from peer_addr
        let mut datagram = Vec::new();
        UdpHeader::new(0, WireAddress::from(peer_addr))
            .write_to_stream(&mut datagram)
            .unwrap();
        datagram.extend_from_slice(b"punch_ack_payload");

        let relay_endpoint: SocketAddr = "127.0.0.1:45240".parse().unwrap();

        // Simulate incoming relay datagram
        shared
            .handle_incoming_relay_datagram(&datagram, relay_endpoint, relay_endpoint)
            .await;

        // Verify flow received the packet with source preserved
        let (source, payload) = tokio::time::timeout(std::time::Duration::from_millis(200), rx.recv())
            .await
            .expect("timeout waiting for demuxed datagram")
            .expect("channel closed");

        assert_eq!(source, peer_addr);
        assert_eq!(payload, b"punch_ack_payload");

        // Deregister flow
        shared.deregister_flow(conn_id).await;
    }
}

async fn handle_dns_over_tcp_session(
    mut udp_stack: IpStackUdpStream,
    server_addr: SocketAddr,
    proxy_handler: Arc<Mutex<dyn ProxyHandler>>,
    ipv6_enabled: bool,
) -> crate::Result<()> {
    let mut server = TcpStream::connect(server_addr)
        .await
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

#[cfg(test)]
mod no_proxy_stats_tests {
    use super::*;

    #[tokio::test]
    async fn no_proxy_metrics_include_tcp_and_udp_statistics() {
        let host_route_stats = Arc::new(Mutex::new(HashMap::new()));
        let diag = DiagServer::noop();
        let target = WireAddress::SocketAddress("192.0.2.10:443".parse().unwrap());
        let observed_at = Timestamp::now();
        let upload = TransferRateSample {
            bytes: 1_000,
            duration_micros: 1_000_000,
            data_span_micros: 1_000_000,
            event_count: 3,
            observed_at,
        };
        let download = TransferRateSample {
            bytes: 2_000,
            duration_micros: 1_000_000,
            data_span_micros: 1_000_000,
            event_count: 3,
            observed_at,
        };

        record_no_proxy_attempt(&host_route_stats, &diag, target.clone(), Duration::from_millis(50), true).await;
        record_no_proxy_transfer_samples(&host_route_stats, &diag, target.clone(), Some(upload), Some(download), false).await;
        record_no_proxy_transfer_samples(&host_route_stats, &diag, target.clone(), Some(upload), Some(download), true).await;

        let key = HostRouteKey::new(target, ObservedRoute::NoProxy);
        let stats = host_route_stats.lock().await;
        let metric = stats.get(&key).unwrap().metric(key, Timestamp::now());

        assert_eq!(metric.connect_latency_ms, Some(50.0));
        assert_eq!(metric.connect_success_rate, Some(1.0));
        assert_eq!(metric.upload_bytes_per_sec, Some(1_000.0));
        assert_eq!(metric.download_bytes_per_sec, Some(2_000.0));
        assert_eq!(metric.udp_upload_bytes_per_sec, Some(1_000.0));
        assert_eq!(metric.udp_download_bytes_per_sec, Some(2_000.0));
    }

    #[tokio::test]
    async fn no_proxy_tcp_copy_records_rate_from_forwarded_writes() {
        let host_route_stats: HostRouteStatsMap = Arc::new(Mutex::new(HashMap::new()));
        let diag = DiagServer::noop();
        let target = WireAddress::SocketAddress("192.0.2.10:443".parse().unwrap());
        let (mut source, mut source_reader) = tokio::io::duplex(4096);
        let (mut destination_writer, mut destination) = tokio::io::duplex(4096);

        let copy = copy_direction_with_stats(
            &mut source_reader,
            &mut destination_writer,
            Instant::now(),
            host_route_stats.clone(),
            diag.clone(),
            target.clone(),
            false,
            true,
        );
        let send = async {
            for byte in 0..4u8 {
                source.write_all(&[byte; 128]).await.unwrap();
                tokio::time::sleep(Duration::from_millis(350)).await;
            }
            source.shutdown().await.unwrap();
        };
        let (copied, ()) = tokio::join!(copy, send);
        let (copied, sample) = copied.unwrap();
        assert_eq!(copied, 512);
        assert!(sample.is_none_or(|sample| sample.event_count > 0));

        let mut received = Vec::new();
        destination.read_to_end(&mut received).await.unwrap();
        assert_eq!(received.len(), 512);

        let key = HostRouteKey::new(target, ObservedRoute::NoProxy);
        let stats = host_route_stats.lock().await;
        let metric = stats.get(&key).unwrap().metric(key, Timestamp::now());
        assert!(metric.upload_bytes_per_sec.is_some());
        assert!(metric.upload_rate_summary.is_some_and(|summary| summary.sample_count > 0));
        assert!(metric.upload_sample.is_some_and(|sample| sample.event_count > 0));
    }
}
