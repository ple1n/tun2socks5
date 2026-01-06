use anyhow::{anyhow, bail};
use concurrent_map::{ConcurrentMap, Maximum, Minimum};
use crossbeam::queue::{ArrayQueue, SegQueue};
use futures::{FutureExt, SinkExt, StreamExt};
use id_alloc::lock_alloc::Alloc;
use id_alloc::opool::RcGuard;
use quick_cache::sync::Cache;
use quick_cache::{DefaultHashBuilder, Lifecycle, UnitWeighter};
use serde::{Deserialize, Serialize};
use socks5_impl::protocol::WireAddress;
use std::collections::{BTreeSet, HashMap, HashSet};
use std::future::Future;
use std::hash::{Hash, RandomState};
use std::num::NonZeroUsize;
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::task::{ready, Context, Poll};
use std::time::{Duration, Instant};
use std::{net::IpAddr, str::FromStr};
use tokio::sync::RwLock;
use tokio::time::sleep;
use tracing::{info, trace, warn};
use trust_dns_proto::op::MessageType;
use trust_dns_proto::{
    op::{Message, ResponseCode},
    rr::{record_type::RecordType, Name, RData, Record},
};
use twox_hash::xxhash3_128;

pub fn build_dns_response(mut request: Message, domain: &str, ip: IpAddr, ttl: u32) -> Result<Message> {
    let record = match ip {
        IpAddr::V4(ip) => {
            let mut record = Record::with(Name::from_str(domain)?, RecordType::A, ttl);
            record.set_data(Some(RData::A(ip.into())));
            record
        }
        IpAddr::V6(ip) => {
            let mut record = Record::with(Name::from_str(domain)?, RecordType::AAAA, ttl);
            record.set_data(Some(RData::AAAA(ip.into())));
            record
        }
    };

    // We must indicate that this message is a response. Otherwise, implementations may not
    // recognize it.
    request.set_message_type(MessageType::Response);

    request.add_answer(record);
    Ok(request)
}

pub fn remove_ipv6_entries(message: &mut Message) {
    message
        .answers_mut()
        .retain(|answer| !matches!(answer.data(), Some(RData::AAAA(_))));
}

pub fn extract_ipaddr_from_dns_message(message: &Message) -> Result<IpAddr> {
    if message.response_code() != ResponseCode::NoError {
        bail!(format!("{:?}", message.response_code()))
    }
    let mut cname = None;
    for answer in message.answers() {
        match answer.data().ok_or(anyhow!("DNS response not contains answer data"))? {
            RData::A(addr) => {
                return Ok(IpAddr::V4((*addr).into()));
            }
            RData::AAAA(addr) => {
                return Ok(IpAddr::V6((*addr).into()));
            }
            RData::CNAME(name) => {
                cname = Some(name.to_utf8());
            }
            _ => {}
        }
    }
    if let Some(cname) = cname {
        bail!(cname)
    }
    bail!("{:?}", message.answers())
}

pub fn extract_domain_from_dns_message(message: &Message) -> Result<String> {
    let query = message.queries().get(0).ok_or(anyhow!("DnsRequest no query body"))?;
    let name = query.name().to_string();
    Ok(name)
}

pub fn parse_data_to_dns_message(data: &[u8], used_by_tcp: bool) -> Result<Message> {
    if used_by_tcp {
        if data.len() < 2 {
            bail!("invalid dns data")
        }
        let len = u16::from_be_bytes([data[0], data[1]]) as usize;
        let data = data.get(2..len + 2).ok_or(anyhow!("invalid dns data"))?;
        return parse_data_to_dns_message(data, false);
    }
    let message = Message::from_vec(data).map_err(|e| anyhow!(e.to_string()))?;
    Ok(message)
}

use crate::error::Result;
use crate::{ArgProxy, POOL_SIZE};

use bimap::{BiHashMap, BiMap};
use id_alloc::{lock_alloc, IDAlloc, IPOps, Ipv4A, Ipv6A, Ipv6Network};
use id_alloc::{Ipv4Network, NetRange};
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4};
use std::ops::{Deref, RangeInclusive};

#[derive(Serialize, Deserialize, Debug)]
pub struct DNSState<R: Hash + Eq, L: Hash + Eq> {
    pub map: HashMap<R, L>,
    pub subnet: Ipv4Network,
}

#[derive(Debug)]
pub enum VDNSRES {
    SpecialHandling(TUNResponse),
    NormalProxying,
    ERR,
}

pub struct VirtDNSAsync {
    pub subnet: Ipv4Network,
    pub range: RangeInclusive<Ipv4A>,
    pub handle: VirtDNSHandle,
}

type PoolEntry = Arc<PoolEntryT>;
type EvictedQ = Arc<SegQueue<Ipv4A>>;

pub struct PoolEntryT {
    pub lock: RcGuard<lock_alloc::Allocator<Ipv4A>, Ipv4A>,
    pub pinned: bool,
}

#[derive(Clone)]
pub struct VirtDNSHandle {
    f_ip: ConcurrentMap<Ipv4A, IPKeyEntry>,
    ip6: ConcurrentMap<Ipv6A, TUNResponse>,
    pub subnet6: Ipv6Network,
    f_domain: Arc<Cache<String, DomainEntry, UnitWeighter, DefaultHashBuilder, IPEviction>>,
    alloc: lock_alloc::Alloc<Ipv4A>,
    range: RangeInclusive<Ipv4A>,
    evicted: EvictedQ,
    pub aaaa_only: bool,
}

#[derive(Clone)]
pub enum DomainEntry {
    Pool(PoolEntry),
    Pinned(Ipv4A),
}

impl DomainEntry {
    pub fn addr(&self) -> Ipv4Addr {
        self.addr_a().addr
    }
    pub fn addr_a(&self) -> Ipv4A {
        match self {
            DomainEntry::Pinned(val) => *val,
            DomainEntry::Pool(val) => *val.lock,
        }
    }
}

#[derive(Clone)]
/// Eviction is depedent on LRU(domain -> IP)
struct IPEviction {
    evicted: EvictedQ,
}

impl Lifecycle<String, DomainEntry> for IPEviction {
    type RequestState = ();
    fn is_pinned(&self, key: &String, val: &DomainEntry) -> bool {
        match val {
            DomainEntry::Pinned(_) => true,
            DomainEntry::Pool(p) => p.pinned,
        }
    }
    fn begin_request(&self) -> Self::RequestState {}
    fn on_evict(&self, state: &mut Self::RequestState, key: String, val: DomainEntry) {
        match val {
            DomainEntry::Pinned(ip) => {
                warn!("evicting pinned {}", ip.addr);
            }
            DomainEntry::Pool(val) => {
                info!("evict {} -> {:?}", key, val.lock);
                self.evicted.push(*val.lock);
            }
        }
    }
}

// when a client queries DNS, an IP is allocated to a domain
// the clients will believe the IP associates with the domain for indefinite time
// there is no way to determine when the clients stop believing this
// ofc there is usually an expiry time about DNS
// here we just bound it with LRU, to prevent exhaustion of IP pool

#[derive(Clone)]
struct IPKeyEntry {
    domain: TUNResponse,
    lifetime: Option<PoolEntry>,
}

#[derive(Clone, Debug)]
pub enum TUNResponse {
    ProxiedHost(String),
    /// Warning. The connection is made by TUN process, which exists in SRC NS.
    NATByTUN(SocketAddr),
    Direct(SocketAddr),
    Files(PathBuf),
    /// When the user has properly configured routing
    Unreachable,
    SpecifiedProxy(
        WireAddress,
        ArgProxy
    )
}

const LRU: usize = 4096;

// DNS metrics
const LRU_IP_HITS: AtomicUsize = AtomicUsize::new(0);
const DOMAIN_HITS: AtomicUsize = AtomicUsize::new(0);
const IP_HITS: AtomicUsize = AtomicUsize::new(0);

#[test]
fn init_virtdns() {
    let virt = VirtDNSAsync::default(POOL_SIZE).unwrap();
    dbg!(&virt.handle.subnet6);
    let net = virt.handle.subnet6;
    println!("{:b}", net.mask().to_bits());
    println!("{:b}", !net.mask().to_bits());
    let hash = xxhash3_128::Hasher::oneshot("veth.host6.".as_bytes());
    println!("hash, {:b}", hash);
    let truncated = hash & !net.mask().to_bits();
    let net = truncated | net.network().to_bits();
    println!("ip {:?}", net);
    let ip = Ipv6Addr::from_bits(net);
    println!("ip {:?}", ip);
}

#[test]
fn test_hash() {
    let hash = xxhash3_128::Hasher::oneshot("veth.host6.".as_bytes());
    println!("hash, {}", hash);
}

impl VirtDNSAsync {
    pub fn default(host_cap: usize) -> Result<Self> {
        let subnet: Ipv4Network = "198.18.0.0/16".parse()?;
        assert!(host_cap < subnet.size() as usize);
        let range = subnet.range(0);
        let concmap: ConcurrentMap<Ipv4A, IPKeyEntry> = Default::default();
        let concmap6: ConcurrentMap<_, _> = Default::default();
        let ev: Arc<SegQueue<Ipv4A>> = Default::default();
        let virt = Self {
            range: range.clone(),
            handle: VirtDNSHandle {
                subnet6: "fc00::/7".parse()?,
                aaaa_only: true,

                f_domain: Arc::new(Cache::with(
                    LRU,
                    LRU as u64,
                    UnitWeighter,
                    DefaultHashBuilder::default(),
                    IPEviction { evicted: ev.clone() },
                )),
                evicted: ev,
                f_ip: concmap,
                alloc: Alloc::init(
                    Ipv4A {
                        addr: subnet.ip(),
                        host: 16,
                    },
                    host_cap as usize,
                ),
                range,
                ip6: concmap6,
            },
            subnet,
        };

        Ok(virt)
    }
}

impl VirtDNSHandle {
    /// Convert a domain name into a deterministic IPv6 address inside `self.subnet6`.
    ///
    /// The algorithm hashes the provided domain string using xxhash3_128, takes
    /// the low-order host bits (clearing the network mask bits) and then ORs
    /// them with the subnet network base bits to produce an `Ipv6Addr` inside
    /// `self.subnet6`.
    pub fn domain_to_ipv6(&self, domain: &str) -> Ipv6Addr {
        // Compute 128-bit hash of domain
        let hash = xxhash3_128::Hasher::oneshot(domain.as_bytes());

        // network mask and network base as 128-bit integers
        let mask_bits = self.subnet6.mask().to_bits();
        let network_bits = self.subnet6.network().to_bits();

        // keep only host bits from hash, then set network bits
        let truncated = hash & !mask_bits;
        let combined = truncated | network_bits;

        Ipv6Addr::from_bits(combined)
    }

    pub fn respond_v6(&self, dom: String) -> Result<Ipv6Addr> {
        let ip = self.domain_to_ipv6(&dom);
        let ipa = self.ipv6a(ip);
        self.ip6.insert(ipa, TUNResponse::ProxiedHost(dom));
        Ok(ip)
    }

    pub async fn periodic_report(self) {
        // tokio::spawn(async move {
        //     loop {
        //         tokio::time::sleep(Duration::from_secs(1)).await;
        //         info!("LRU size = {}, DNS map = {}", self.lru_domains.len(), self.domains.len());
        //     }
        // });
    }
    pub fn to_respond_in_dns(&self, dom: String) -> Result<Ipv4Addr> {
        trace!("virtdns: alloc {}", dom);
        self.apply_evictions();
        IP_HITS.fetch_add(1, Ordering::SeqCst);
        if let Some(hit) = self.f_domain.get(&dom) {
            let addr = hit.addr();
            Ok(addr)
        } else {
            let own = Arc::new(PoolEntryT {
                lock: self.alloc.pool.clone().get_rc(),
                pinned: false,
            });
            trace!("got object from pool");
            let addr = own.lock.addr;
            self.f_ip.insert(
                *own.lock,
                IPKeyEntry {
                    domain: TUNResponse::ProxiedHost(dom.clone()),
                    lifetime: own.clone().into(),
                },
            );
            self.f_domain.insert(dom, DomainEntry::Pool(own));
            Ok(addr)
        }
    }
    pub fn apply_evictions(&self) {
        loop {
            if let Some(ev) = self.evicted.pop() {
                self.f_ip.remove(&ev);
            } else {
                break;
            }
        }
    }
    pub fn receive_query(&self, data: &[u8]) -> Result<Vec<u8>> {
        let message = parse_data_to_dns_message(data, false)?;
        let qname = extract_domain_from_dns_message(&message)?;
        info!("VirtDNS recved {}", qname);
        if self.aaaa_only {
            // V4 mappings are still handled, but only for presets
            // New mappings aren't added if they don't exist
            if let Some(hit) = self.f_domain.get(&qname) {
                let addr = hit.addr();
                let message = build_dns_response(message, &qname, addr.into(), 5)?;
                Ok(message.to_vec()?)
            } else {
                let ip = self.respond_v6(qname.clone())?;
                let message = build_dns_response(message, &qname, ip.into(), 5)?;
                Ok(message.to_vec()?)
            }
        } else {
            let ip = self.to_respond_in_dns(qname.clone())?;
            let message = build_dns_response(message, &qname, ip.into(), 5)?;
            Ok(message.to_vec()?)
        }
    }
    pub fn process(&self, addr: SocketAddr) -> VDNSRES {
        match addr {
            SocketAddr::V4(v4) => {
                let v4a = self.ipv4a(v4.ip().to_owned());
                let entry = if let Some(IPKeyEntry { domain, lifetime }) = self.f_ip.get(&v4a) {
                    Some(domain)
                } else {
                    None
                };

                if self.range.contains(&v4.ip().to_owned().into()) {
                    if !entry.is_some() {
                        warn!("virtdns: address with no associated domain, {}", &v4);
                        return VDNSRES::ERR;
                    }
                }
                match entry {
                    None => VDNSRES::NormalProxying,
                    Some(h) => VDNSRES::SpecialHandling(h),
                }
            }
            SocketAddr::V6(v6) => {
                let v6a = self.ipv6a(v6.ip().to_owned());
                let entry = self.ip6.get(&v6a);
                match entry {
                    None => {
                        if self.subnet6.contains(*v6.ip()) {
                            warn!("VirtDNSv6, entry not found");
                            VDNSRES::ERR
                        } else {
                            VDNSRES::NormalProxying
                        }
                    }
                    Some(h) => VDNSRES::SpecialHandling(h),
                }
            }
            k => VDNSRES::NormalProxying,
        }
    }
    pub fn ipv4a(&self, ip: Ipv4Addr) -> Ipv4A {
        Ipv4A::new(ip, self.alloc.interval.host)
    }
    pub fn ipv6a(&self, ip: Ipv6Addr) -> Ipv6A {
        Ipv6A::new(ip, 128 - 7)
    }
    pub fn pin(&self, v4: Option<Ipv4Addr>, dom: String, tun: TUNResponse) -> Result<()> {
        warn!("pin {:?} -> {}", v4, dom);

        self.apply_evictions();
        // Each data is a row with 3 columns.
        if let Some(hit) = self.f_domain.get(&dom) {
            self.f_ip.remove(&hit.addr_a());
        }

        if let Some(v4) = v4 {
            let v4a = self.ipv4a(v4);
            if self.range.contains(&v4a) {
                warn!("manually assigned IP should not fall into Virt DNS exclusive subnet");
                bail!("invalid IP designation");
            }
            self.f_ip.insert(
                v4a,
                IPKeyEntry {
                    domain: tun,
                    lifetime: None,
                },
            );
            self.f_domain.insert(dom, DomainEntry::Pinned(v4a));
        } else {
            let own = Arc::new(PoolEntryT {
                lock: self.alloc.pool.clone().get_rc(),
                pinned: false,
            });
            trace!("got object from pool");
            let addr = own.lock.addr;
            self.f_ip.insert(
                *own.lock,
                IPKeyEntry {
                    domain: tun,
                    lifetime: own.clone().into(),
                },
            );
            self.f_domain.insert(dom, DomainEntry::Pool(own));
        };

        Ok(())
    }
    pub fn unpin(&self, dom: String) {
        todo!()
    }
}
