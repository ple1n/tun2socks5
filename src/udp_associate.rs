use anyhow::{anyhow, bail};
use diag::{ConnId, DiagEvent, DiagServer, SocksEndpointStatus, SocksOpKind, Timestamp};
use socks5_impl::protocol::{StreamOperation, UdpHeader, UserKey, Version, WireAddress};
use std::{
    collections::{HashMap, HashSet},
    hash::Hash,
    net::{IpAddr, SocketAddr},
    sync::{
        atomic::{AtomicU64, AtomicUsize, Ordering},
        Arc,
    },
    time::{Duration, Instant},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpStream, UdpSocket},
    sync::{mpsc, oneshot, RwLock},
    time::sleep,
};
use tracing::{debug, error, info, trace, warn};

use crate::{
    directions::{IncomingDataEvent, IncomingDirection, OutgoingDirection},
    parse_socks5_udp_datagram,
    proxy_handler::{ConnectionManager, ProxyHandler},
    session_info::SessionInfo,
    socks::SocksProxyManager,
};

/// Resolve the effective UDP relay destination given the proxy's reported BND address.
///
/// RFC 1928 stipulates: "A value of all zeros indicates that the address of the relay
/// is the address of the SOCKS server as seen by the client."
pub fn resolve_effective_relay(raw_bnd: &WireAddress, server_addr: SocketAddr) -> SocketAddr {
    match raw_bnd {
        WireAddress::SocketAddress(addr) => {
            if addr.ip().is_unspecified() {
                SocketAddr::new(server_addr.ip(), addr.port())
            } else {
                *addr
            }
        }
        WireAddress::DomainAddress(_domain, port) => SocketAddr::new(server_addr.ip(), *port),
    }
}

pub struct ActiveUdpRelay {
    pub socket: Arc<UdpSocket>,
    pub raw_bnd: WireAddress,
    pub effective_bnd: SocketAddr,
}

#[derive(Clone)]
struct FlowRegistration {
    local_addr: SocketAddr,
    peer_addr: SocketAddr,
    target: WireAddress,
    inbound_tx: mpsc::Sender<(WireAddress, Vec<u8>)>,
}

#[derive(Default)]
struct FlowRegistry {
    by_id: HashMap<ConnId, FlowRegistration>,
    by_peer: HashMap<SocketAddr, HashSet<ConnId>>,
    by_peer_ip: HashMap<IpAddr, HashSet<ConnId>>,
    by_target: HashMap<WireAddress, HashSet<ConnId>>,
}

impl FlowRegistry {
    fn register(&mut self, conn_id: ConnId, registration: FlowRegistration) {
        self.deregister(conn_id);
        insert_index(&mut self.by_peer, registration.peer_addr, conn_id);
        insert_index(&mut self.by_peer_ip, registration.peer_addr.ip(), conn_id);
        insert_index(&mut self.by_target, canonical_wire_address(&registration.target), conn_id);
        self.by_id.insert(conn_id, registration);
    }

    fn deregister(&mut self, conn_id: ConnId) {
        if let Some(registration) = self.by_id.remove(&conn_id) {
            remove_index(&mut self.by_peer, &registration.peer_addr, conn_id);
            remove_index(&mut self.by_peer_ip, &registration.peer_addr.ip(), conn_id);
            remove_index(&mut self.by_target, &canonical_wire_address(&registration.target), conn_id);
        }
    }

    fn match_flow(&self, remote_source: &WireAddress) -> Option<&FlowRegistration> {
        let conn_id = match remote_source {
            WireAddress::SocketAddress(addr) => lookup_index(&self.by_peer, addr)
                .or_else(|| lookup_index(&self.by_target, remote_source))
                .or_else(|| lookup_index(&self.by_peer_ip, &addr.ip())),
            WireAddress::DomainAddress(..) => lookup_index(&self.by_target, &canonical_wire_address(remote_source)),
        }
        .or_else(|| {
            if self.by_id.len() == 1 {
                self.by_id.keys().next().copied()
            } else {
                None
            }
        })?;
        self.by_id.get(&conn_id)
    }
}

fn insert_index<K: Eq + Hash>(index: &mut HashMap<K, HashSet<ConnId>>, key: K, conn_id: ConnId) {
    index.entry(key).or_default().insert(conn_id);
}

fn remove_index<K: Eq + Hash>(index: &mut HashMap<K, HashSet<ConnId>>, key: &K, conn_id: ConnId) {
    if let Some(ids) = index.get_mut(key) {
        ids.remove(&conn_id);
        if ids.is_empty() {
            index.remove(key);
        }
    }
}

fn lookup_index<K: Eq + Hash>(index: &HashMap<K, HashSet<ConnId>>, key: &K) -> Option<ConnId> {
    let ids = index.get(key)?;
    (ids.len() == 1).then(|| ids.iter().next().copied()).flatten()
}

fn canonical_wire_address(address: &WireAddress) -> WireAddress {
    match address {
        WireAddress::SocketAddress(addr) => WireAddress::SocketAddress(*addr),
        WireAddress::DomainAddress(domain, port) => WireAddress::DomainAddress(domain.trim_end_matches('.').to_ascii_lowercase(), *port),
    }
}

pub struct SharedUdpAssociate {
    server_addr: SocketAddr,
    credentials: Option<UserKey>,
    diag: DiagServer,
    current_relay: Arc<RwLock<Option<Arc<ActiveUdpRelay>>>>,
    status: Arc<RwLock<SocksEndpointStatus>>,
    flows: Arc<RwLock<FlowRegistry>>,
    pkts_tx: AtomicU64,
    pkts_rx_datagrams: AtomicU64,
    pkts_rx: AtomicU64,
    pkts_rx_source_rejected: AtomicU64,
    pkts_rx_parse_errors: AtomicU64,
    pkts_rx_unmatched: AtomicU64,
    pkts_rx_delivery_dropped: AtomicU64,
    pkts_rx_queued: AtomicU64,
    bytes_tx: AtomicU64,
    bytes_rx: AtomicU64,
    stats_epoch: Instant,
    last_stats_emit_ms: AtomicU64,
    active_flow_count: AtomicUsize,
    shutdown_tx: RwLock<Option<oneshot::Sender<()>>>,
}

impl SharedUdpAssociate {
    pub fn new(server_addr: SocketAddr, credentials: Option<UserKey>, diag: DiagServer) -> Arc<Self> {
        let (shutdown_tx, shutdown_rx) = oneshot::channel();
        let associate = Arc::new(Self {
            server_addr,
            credentials,
            diag,
            current_relay: Arc::new(RwLock::new(None)),
            status: Arc::new(RwLock::new(SocksEndpointStatus::Connecting)),
            flows: Arc::new(RwLock::new(FlowRegistry::default())),
            pkts_tx: AtomicU64::new(0),
            pkts_rx_datagrams: AtomicU64::new(0),
            pkts_rx: AtomicU64::new(0),
            pkts_rx_source_rejected: AtomicU64::new(0),
            pkts_rx_parse_errors: AtomicU64::new(0),
            pkts_rx_unmatched: AtomicU64::new(0),
            pkts_rx_delivery_dropped: AtomicU64::new(0),
            pkts_rx_queued: AtomicU64::new(0),
            bytes_tx: AtomicU64::new(0),
            bytes_rx: AtomicU64::new(0),
            stats_epoch: Instant::now(),
            last_stats_emit_ms: AtomicU64::new(0),
            active_flow_count: AtomicUsize::new(0),
            shutdown_tx: RwLock::new(Some(shutdown_tx)),
        });

        let worker = Arc::clone(&associate);
        tokio::spawn(async move {
            worker.run_loop(shutdown_rx).await;
        });

        associate
    }

    pub fn server_addr(&self) -> SocketAddr {
        self.server_addr
    }

    pub async fn current_status(&self) -> SocksEndpointStatus {
        self.status.read().await.clone()
    }

    /// Wait until the background associate has a relay socket ready.
    pub async fn wait_until_active(&self) -> crate::Result<()> {
        loop {
            if self.current_relay.read().await.is_some() {
                return Ok(());
            }
            if let SocksEndpointStatus::Closed { reason } = self.current_status().await {
                bail!("SOCKS UDP associate closed: {reason}");
            }
            sleep(Duration::from_millis(10)).await;
        }
    }

    fn set_status(&self, new_status: SocksEndpointStatus) {
        let diag = self.diag.clone();
        let server_addr = self.server_addr;
        let status_clone = new_status.clone();
        tokio::spawn(async move {
            diag.emit(DiagEvent::SocksEndpointStateChanged {
                ts: Timestamp::now(),
                op: SocksOpKind::UdpAssociate,
                proxy_addr: server_addr,
                status: status_clone,
            });
        });
    }

    pub fn emit_stats(&self) {
        self.last_stats_emit_ms.store(
            self.stats_epoch.elapsed().as_millis().min(u64::MAX as u128) as u64,
            Ordering::Relaxed,
        );
        let diag = self.diag.clone();
        let server_addr = self.server_addr;
        let active_flows = self.active_flow_count.load(Ordering::Relaxed);
        let pkts_tx = self.pkts_tx.load(Ordering::Relaxed);
        let pkts_rx_datagrams = self.pkts_rx_datagrams.load(Ordering::Relaxed);
        let pkts_rx = self.pkts_rx.load(Ordering::Relaxed);
        let pkts_rx_source_rejected = self.pkts_rx_source_rejected.load(Ordering::Relaxed);
        let pkts_rx_parse_errors = self.pkts_rx_parse_errors.load(Ordering::Relaxed);
        let pkts_rx_unmatched = self.pkts_rx_unmatched.load(Ordering::Relaxed);
        let pkts_rx_delivery_dropped = self.pkts_rx_delivery_dropped.load(Ordering::Relaxed);
        let pkts_rx_queued = self.pkts_rx_queued.load(Ordering::Relaxed);
        let bytes_tx = self.bytes_tx.load(Ordering::Relaxed);
        let bytes_rx = self.bytes_rx.load(Ordering::Relaxed);

        diag.emit(DiagEvent::SocksEndpointStats {
            ts: Timestamp::now(),
            op: SocksOpKind::UdpAssociate,
            proxy_addr: server_addr,
            active_flows,
            pkts_tx,
            pkts_rx_datagrams,
            pkts_rx,
            pkts_rx_source_rejected,
            pkts_rx_parse_errors,
            pkts_rx_unmatched,
            pkts_rx_delivery_dropped,
            pkts_rx_queued,
            bytes_tx,
            bytes_rx,
        });
    }

    fn emit_stats_if_due(&self) {
        let now_ms = self.stats_epoch.elapsed().as_millis().min(u64::MAX as u128) as u64;
        loop {
            let last_ms = self.last_stats_emit_ms.load(Ordering::Relaxed);
            if now_ms.saturating_sub(last_ms) < 1_000 {
                return;
            }
            if self
                .last_stats_emit_ms
                .compare_exchange(last_ms, now_ms, Ordering::Relaxed, Ordering::Relaxed)
                .is_ok()
            {
                self.emit_stats();
                return;
            }
        }
    }

    pub async fn register_flow(
        &self,
        conn_id: ConnId,
        local_addr: SocketAddr,
        peer_addr: SocketAddr,
        target: WireAddress,
    ) -> mpsc::Receiver<(WireAddress, Vec<u8>)> {
        let (tx, rx) = mpsc::channel(256);
        let registration = FlowRegistration {
            local_addr,
            peer_addr,
            target,
            inbound_tx: tx,
        };

        {
            let mut flows = self.flows.write().await;
            flows.register(conn_id, registration);
            self.active_flow_count.store(flows.by_id.len(), Ordering::Relaxed);
        }

        self.emit_stats();
        rx
    }

    pub async fn deregister_flow(&self, conn_id: ConnId) {
        {
            let mut flows = self.flows.write().await;
            flows.deregister(conn_id);
            self.active_flow_count.store(flows.by_id.len(), Ordering::Relaxed);
        }

        self.emit_stats();
    }

    pub async fn send_datagram(&self, dst: WireAddress, payload: &[u8]) -> crate::Result<()> {
        let relay = {
            let guard = self.current_relay.read().await;
            guard
                .clone()
                .ok_or_else(|| anyhow!("SOCKS UDP associate relay is currently not active"))?
        };

        let mut s5_udp_data = Vec::with_capacity(24 + payload.len());
        UdpHeader::new(0, dst).write_to_stream(&mut s5_udp_data)?;
        s5_udp_data.extend_from_slice(payload);

        relay.socket.send_to(&s5_udp_data, relay.effective_bnd).await?;

        self.pkts_tx.fetch_add(1, Ordering::Relaxed);
        self.bytes_tx.fetch_add(payload.len() as u64, Ordering::Relaxed);
        self.emit_stats_if_due();

        Ok(())
    }

    async fn run_loop(self: Arc<Self>, mut shutdown_rx: oneshot::Receiver<()>) {
        loop {
            *self.status.write().await = SocksEndpointStatus::Connecting;
            self.set_status(SocksEndpointStatus::Connecting);

            let associate_result = tokio::select! {
                _ = &mut shutdown_rx => {
                    info!("Shared UDP associate shutting down");
                    *self.status.write().await = SocksEndpointStatus::Closed { reason: "shutdown".to_string() };
                    self.set_status(SocksEndpointStatus::Closed { reason: "shutdown".to_string() });
                    break;
                }
                res = self.connect_and_associate() => res,
            };

            match associate_result {
                Ok((tcp_stream, raw_bnd, effective_bnd, udp_socket)) => {
                    let socket = Arc::new(udp_socket);
                    let relay = Arc::new(ActiveUdpRelay {
                        socket: socket.clone(),
                        raw_bnd: raw_bnd.clone(),
                        effective_bnd,
                    });

                    *self.current_relay.write().await = Some(relay);
                    let active_status = SocksEndpointStatus::Active {
                        raw_bnd,
                        effective_bnd,
                        relay_local_addr: socket.local_addr().ok(),
                    };
                    *self.status.write().await = active_status.clone();
                    self.set_status(active_status);
                    self.emit_stats();

                    let err = tokio::select! {
                        _ = &mut shutdown_rx => {
                            info!("Shared UDP associate shutting down during session");
                            *self.current_relay.write().await = None;
                            *self.status.write().await = SocksEndpointStatus::Closed { reason: "shutdown".to_string() };
                            self.set_status(SocksEndpointStatus::Closed { reason: "shutdown".to_string() });
                            break;
                        }
                        session_err = self.run_session(tcp_stream, socket, effective_bnd) => session_err,
                    };

                    *self.current_relay.write().await = None;
                    let reason = format!("{}", err);
                    warn!("SOCKS UDP association lost: {}", reason);
                    let reconnect_status = SocksEndpointStatus::Reconnecting { reason };
                    *self.status.write().await = reconnect_status.clone();
                    self.set_status(reconnect_status);
                }
                Err(e) => {
                    let reason = format!("{}", e);
                    warn!("SOCKS UDP associate handshake failed: {}", reason);
                    let reconnect_status = SocksEndpointStatus::Reconnecting { reason };
                    *self.status.write().await = reconnect_status.clone();
                    self.set_status(reconnect_status);
                }
            }

            // Backoff before reconnecting
            tokio::select! {
                _ = &mut shutdown_rx => {
                    break;
                }
                _ = sleep(Duration::from_millis(1500)) => {}
            }
        }
    }

    async fn connect_and_associate(&self) -> crate::Result<(TcpStream, WireAddress, SocketAddr, UdpSocket)> {
        let mut server = TcpStream::connect(self.server_addr)
            .await
            .map_err(|e| anyhow!("proxy server connection refused at {}: {}", self.server_addr, e))?;

        let info = SessionInfo::new(
            "0.0.0.0:0".parse().unwrap(),
            WireAddress::unspecified(),
            crate::session_info::IpProtocol::Udp,
        );
        let manager = SocksProxyManager::new(self.server_addr, Version::V5, self.credentials.clone());
        let proxy_handler = manager.new_proxy_handler(info, true).await?;

        // Drive the SOCKS handshake
        self.drive_socks_handshake(&mut server, proxy_handler.clone()).await?;

        let raw_bnd = {
            let handler = proxy_handler.lock().await;
            handler
                .get_raw_udp_associate()
                .ok_or_else(|| anyhow!("SOCKS UDP associate reply missing BND address"))?
        };

        let effective_bnd = resolve_effective_relay(&raw_bnd, self.server_addr);
        let bind_addr = if self.server_addr.is_ipv6() { "[::]:0" } else { "0.0.0.0:0" };
        let udp_socket = UdpSocket::bind(bind_addr).await?;

        info!(
            "Shared SOCKS UDP associate established: raw_bnd={}, effective_bnd={}, local_relay={:?}",
            raw_bnd,
            effective_bnd,
            udp_socket.local_addr()
        );

        Ok((server, raw_bnd, effective_bnd, udp_socket))
    }

    async fn drive_socks_handshake(
        &self,
        server: &mut TcpStream,
        proxy_handler: Arc<tokio::sync::Mutex<dyn ProxyHandler>>,
    ) -> crate::Result<()> {
        let mut launched = false;
        let mut handler = proxy_handler.lock().await;
        let dir = OutgoingDirection::ToServer;

        loop {
            if handler.connection_established() {
                break;
            }

            if !launched {
                let data = handler.peek_data(dir).buffer;
                let len = data.len();
                if len == 0 {
                    bail!("proxy_handler launch failed");
                }
                server.write_all(data).await?;
                handler.consume_data(dir, len);
                launched = true;
            }

            let mut buf = [0_u8; 4096];
            let len = server.read(&mut buf).await?;
            if len == 0 {
                bail!("proxy server closed during SOCKS UDP associate handshake");
            }
            let event = IncomingDataEvent {
                direction: IncomingDirection::FromServer,
                buffer: &buf[..len],
            };
            handler.push_data(event).await?;

            let data = handler.peek_data(dir).buffer;
            let len = data.len();
            if len > 0 {
                server.write_all(data).await?;
                handler.consume_data(dir, len);
            }
        }

        Ok(())
    }

    async fn run_session(&self, mut tcp_stream: TcpStream, udp_socket: Arc<UdpSocket>, effective_bnd: SocketAddr) -> anyhow::Error {
        let mut tcp_buf = [0u8; 64];
        let mut udp_buf = [0u8; 65535];

        loop {
            tokio::select! {
                res = tcp_stream.read(&mut tcp_buf) => {
                    match res {
                        Ok(0) => return anyhow!("SOCKS TCP control connection closed (EOF)"),
                        Ok(n) => trace!("SOCKS TCP control stream received {} unexpected bytes", n),
                        Err(e) => return anyhow!("SOCKS TCP control stream error: {}", e),
                    }
                }
                res = udp_socket.recv_from(&mut udp_buf) => {
                    match res {
                        Ok((len, from_addr)) => {
                            self.handle_incoming_relay_datagram(&udp_buf[..len], from_addr, effective_bnd).await;
                        }
                        Err(e) => {
                            return anyhow!("UDP relay socket read error: {}", e);
                        }
                    }
                }
            }
        }
    }

    pub(crate) async fn handle_incoming_relay_datagram(&self, buf: &[u8], from_addr: SocketAddr, effective_bnd: SocketAddr) {
        self.pkts_rx_datagrams.fetch_add(1, Ordering::Relaxed);

        // Accept packets from relay
        if from_addr.ip() != effective_bnd.ip() && from_addr != effective_bnd {
            self.pkts_rx_source_rejected.fetch_add(1, Ordering::Relaxed);
            self.emit_stats_if_due();
            trace!(
                "ignoring UDP datagram from unexpected source {} (expected relay {})",
                from_addr,
                effective_bnd
            );
            return;
        }

        let (remote_source_addr, payload) = match parse_socks5_udp_datagram(buf) {
            Ok(res) => res,
            Err(e) => {
                self.pkts_rx_parse_errors.fetch_add(1, Ordering::Relaxed);
                self.emit_stats_if_due();
                warn!("failed to parse incoming SOCKS5 UDP datagram: {}", e);
                return;
            }
        };

        self.pkts_rx.fetch_add(1, Ordering::Relaxed);
        self.bytes_rx.fetch_add(payload.len() as u64, Ordering::Relaxed);

        let inbound_tx = {
            let flows = self.flows.read().await;
            flows.match_flow(&remote_source_addr).map(|flow| flow.inbound_tx.clone())
        };

        if let Some(inbound_tx) = inbound_tx {
            if inbound_tx.try_send((remote_source_addr, payload.to_vec())).is_ok() {
                self.pkts_rx_queued.fetch_add(1, Ordering::Relaxed);
            } else {
                self.pkts_rx_delivery_dropped.fetch_add(1, Ordering::Relaxed);
            }
        } else {
            self.pkts_rx_unmatched.fetch_add(1, Ordering::Relaxed);
            trace!("no active local flow registered for remote UDP source {}", remote_source_addr);
        }
        self.emit_stats_if_due();
    }
}

#[cfg(test)]
mod flow_registry_tests {
    use super::*;

    #[test]
    fn matches_domain_reply_and_removes_flow_indexes() {
        let mut registry = FlowRegistry::default();
        let conn_id = ConnId(7);
        let (inbound_tx, _inbound_rx) = mpsc::channel(1);
        let peer_addr = "198.18.0.1:45187".parse().unwrap();
        let target = WireAddress::DomainAddress("stun.l.google.com".to_string(), 19302);
        registry.register(
            conn_id,
            FlowRegistration {
                local_addr: "198.18.0.1:45187".parse().unwrap(),
                peer_addr,
                target,
                inbound_tx,
            },
        );

        let reply_source = WireAddress::DomainAddress("STUN.L.GOOGLE.COM.".to_string(), 19302);
        assert_eq!(registry.match_flow(&reply_source).map(|flow| flow.local_addr), Some(peer_addr));

        registry.deregister(conn_id);
        assert!(registry.match_flow(&reply_source).is_none());
        assert!(registry.by_peer.is_empty());
        assert!(registry.by_peer_ip.is_empty());
        assert!(registry.by_target.is_empty());
    }

    #[test]
    fn does_not_route_ambiguous_domain_replies_to_an_arbitrary_flow() {
        let mut registry = FlowRegistry::default();
        let target = WireAddress::DomainAddress("stun.l.google.com".to_string(), 19302);
        let peer_addr = "198.18.0.1:45187".parse().unwrap();
        let (first_tx, _first_rx) = mpsc::channel(1);
        let (second_tx, _second_rx) = mpsc::channel(1);
        for (conn_id, local_addr, inbound_tx) in [
            (ConnId(1), "198.18.0.1:45187".parse().unwrap(), first_tx),
            (ConnId(2), "198.18.0.1:45188".parse().unwrap(), second_tx),
        ] {
            registry.register(
                conn_id,
                FlowRegistration {
                    local_addr,
                    peer_addr,
                    target: target.clone(),
                    inbound_tx,
                },
            );
        }

        let reply_source = WireAddress::DomainAddress("stun.l.google.com".to_string(), 19302);
        assert!(registry.match_flow(&reply_source).is_none());
    }
}
