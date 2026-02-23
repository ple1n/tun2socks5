use anyhow::{anyhow, bail};
use concurrent_map::{ConcurrentMap, Maximum, Minimum};
use crossbeam::queue::{ArrayQueue, SegQueue};
use futures::{FutureExt, SinkExt, StreamExt};
use id_alloc::lock_alloc::Alloc;
use id_alloc::opool::RcGuard;
use index_set::{slot_count, AtomicBitSet, SharedBitSet};
use nsproxy_common::routing::{DropReason, RoutingDecision, VDNSRES};
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

pub struct VirtDNSAsync {
    pub subnet: Ipv4Network,
    pub range: RangeInclusive<Ipv4A>,
    pub handle: VirtDNSHandle,
}

type PoolEntry = Arc<PoolEntryT>;
type EvictedQ = Arc<SegQueue<Ipv4A>>;
type V4BitSet = Arc<AtomicBitSet<{ slot_count::from_bits(2 ^ 16) }>>;

pub struct PoolEntryT {
    pub lock: RcGuard<lock_alloc::Allocator<Ipv4A>, Ipv4A>,
    pub pinned: bool,
}

#[derive(Clone)]
pub struct VirtDNSHandle {
    f_ip: ConcurrentMap<Ipv4A, IPKeyEntry>,
    ip6: Arc<Cache<Ipv6A, RoutingDecision, UnitWeighter, DefaultHashBuilder, Ipv6Eviction>>,
    pub subnet6: Ipv6Network,
    f_domain: Arc<Cache<String, DomainEntry, UnitWeighter, DefaultHashBuilder, IPEviction>>,
    alloc_v4: lock_alloc::Alloc<Ipv4A>,
    range: RangeInclusive<Ipv4A>,
    evicted: EvictedQ,
    pub aaaa_only: bool,
    v4_set: Arc<AtomicBitSet<{ slot_count::from_bits(2 ^ 16) }>>,
}

#[derive(Clone)]
pub enum DomainEntry {
    Pool(PoolEntry),
    Pinned(Ipv4A),
    /// Allocated from the atomic bitset; freed on LRU eviction.
    BitSet(Ipv4A),
}

impl DomainEntry {
    pub fn addr(&self) -> Ipv4Addr {
        self.addr_a().addr
    }
    pub fn addr_a(&self) -> Ipv4A {
        match self {
            DomainEntry::Pinned(val) => *val,
            DomainEntry::Pool(val) => *val.lock,
            DomainEntry::BitSet(val) => *val,
        }
    }
}

#[derive(Clone)]
/// Eviction is depedent on LRU(domain -> IP)
struct IPEviction {
    evicted: EvictedQ,
    /// Shared bitset for BitSet-variant entries; base is the subnet network address.
    v4_set: V4BitSet,
    v4_base: u32,
}

impl Lifecycle<String, DomainEntry> for IPEviction {
    type RequestState = ();
    fn is_pinned(&self, _key: &String, val: &DomainEntry) -> bool {
        match val {
            DomainEntry::Pinned(_) => true,
            DomainEntry::Pool(p) => p.pinned,
            DomainEntry::BitSet(_) => false,
        }
    }
    fn begin_request(&self) -> Self::RequestState {}
    fn on_evict(&self, _state: &mut Self::RequestState, key: String, val: DomainEntry) {
        match val {
            DomainEntry::Pinned(ip) => {
                warn!("evicting pinned {}", ip.addr);
            }
            DomainEntry::Pool(val) => {
                info!("evict {} -> {:?}", key, val.lock);
                self.evicted.push(*val.lock);
            }
            DomainEntry::BitSet(v4a) => {
                let idx = (u32::from(v4a.addr) - self.v4_base) as usize;
                info!("evict bitset {} -> {} (bit {})", key, v4a.addr, idx);
                self.v4_set.remove(idx);
            }
        }
    }
}

/// IPv6 eviction for unbounded cache cleanup
#[derive(Clone)]
struct Ipv6Eviction;

impl Lifecycle<Ipv6A, RoutingDecision> for Ipv6Eviction {
    type RequestState = ();
    fn is_pinned(&self, _key: &Ipv6A, _val: &RoutingDecision) -> bool {
        false
    }
    fn begin_request(&self) -> Self::RequestState {}
    fn on_evict(&self, _state: &mut Self::RequestState, key: Ipv6A, val: RoutingDecision) {
        info!("evict ipv6 {:?} -> {:?}", key, val);
    }
}

// when a client queries DNS, an IP is allocated to a domain
// the clients will believe the IP associates with the domain for indefinite time
// there is no way to determine when the clients stop believing this
// ofc there is usually an expiry time about DNS
// here we just bound it with LRU, to prevent exhaustion of IP pool

#[derive(Clone)]
struct IPKeyEntry {
    domain: RoutingDecision,
    lifetime: Option<PoolEntry>,
}

const LRU: usize = 16384;
const LRU_IPV6: usize = 8192;

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

#[test]
fn test_uniset() {
    let set: index_set::AtomicBitSet<{ slot_count::from_bits(2 ^ 24) }> = index_set::AtomicBitSet::new();
    let k = set.set_next_free_bit();
    let k = set.set_next_free_bit();
    set.remove(1);
    let k = set.set_next_free_bit();
    println!("{:?}", k);
}

pub static VIRT_IP: &str = "fc00::/7";

pub fn default_virtip() -> Ipv6Network {
    VIRT_IP.parse().unwrap()
}

impl VirtDNSAsync {
    pub fn default(host_cap: usize) -> Result<Self> {
        let subnet: Ipv4Network = "198.18.0.0/16".parse()?;
        assert!(host_cap < subnet.size() as usize);
        let range = subnet.range(0);
        let concmap: ConcurrentMap<Ipv4A, IPKeyEntry> = Default::default();
        let ev: Arc<SegQueue<Ipv4A>> = Default::default();
        let mut v4_set: V4BitSet = Arc::new(AtomicBitSet::new());
        let v4_base = u32::from(subnet.ip());
        v4_set.set_next_free_bit();
        v4_set.set_next_free_bit();
        let virt = Self {
            range: range.clone(),
            handle: VirtDNSHandle {
                subnet6: default_virtip(),
                aaaa_only: false,
                f_domain: Arc::new(Cache::with(
                    LRU,
                    LRU as u64,
                    UnitWeighter,
                    DefaultHashBuilder::default(),
                    IPEviction {
                        evicted: ev.clone(),
                        v4_set: v4_set.clone(),
                        v4_base,
                    },
                )),
                ip6: Arc::new(Cache::with(
                    LRU_IPV6,
                    LRU_IPV6 as u64,
                    UnitWeighter,
                    DefaultHashBuilder::default(),
                    Ipv6Eviction,
                )),
                evicted: ev,
                f_ip: concmap,
                alloc_v4: Alloc::init(
                    Ipv4A {
                        addr: subnet.ip(),
                        host: 16,
                    },
                    host_cap as usize,
                ),
                range,
                v4_set,
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
    #[inline]
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

    pub async fn periodic_report(self) {
        // tokio::spawn(async move {
        //     loop {
        //         tokio::time::sleep(Duration::from_secs(1)).await;
        //         info!("LRU size = {}, DNS map = {}", self.lru_domains.len(), self.domains.len());
        //     }
        // });
    }
    #[inline]
    pub fn respond_by_pool(&self, dom: String) -> Result<Ipv4Addr> {
        // Fast path: check cache first without evictions
        if let Some(hit) = self.f_domain.get(&dom) {
            return Ok(hit.addr());
        }

        trace!("virtdns: alloc {}", dom);

        // Slow path: allocate new entry and apply evictions
        let own = Arc::new(PoolEntryT {
            lock: self.alloc_v4.pool.clone().get_rc(),
            pinned: false,
        });
        let addr = own.lock.addr;
        let ip_key = *own.lock;

        // Insert both mappings before eviction to ensure atomicity
        self.f_domain.insert(dom.clone(), DomainEntry::Pool(own.clone()));
        self.f_ip.insert(
            ip_key,
            IPKeyEntry {
                domain: RoutingDecision::HostOverProxy(dom),
                lifetime: own.into(),
            },
        );

        // Apply evictions after successful allocation
        self.apply_evictions();

        Ok(addr)
    }
    pub fn apply_evictions(&self) {
        // Batch process evictions - up to 16 at once to amortize cost
        for _ in 0..16 {
            if let Some(ev) = self.evicted.pop() {
                self.f_ip.remove(&ev);
            } else {
                break;
            }
        }
    }

    /// Allocate a virtual IPv4 from the atomic bitset.
    ///
    /// Claims the next free bit in `v4_set`, then reconstructs the IPv4 by
    /// OR-ing the bit index (host part) with the network base taken from
    /// `self.range`. Returns `None` when the pool is exhausted.
    #[inline]
    pub fn alloc_bitset(&self) -> Option<Ipv4Addr> {
        let idx = self.v4_set.set_next_free_bit()?;
        let base = u32::from(self.range.start().addr);
        Some(Ipv4Addr::from(base | idx as u32))
    }

    /// Release a bitset-allocated virtual IPv4 back to the pool.
    ///
    /// Recovers the host-part index by subtracting the network base, then
    /// clears the corresponding bit in `v4_set`.
    #[inline]
    pub fn dealloc_bitset(&self, ip: Ipv4Addr) {
        let base = u32::from(self.range.start().addr);
        let idx = (u32::from(ip) - base) as usize;
        self.v4_set.remove(idx);
    }

    /// Respond to an A query using the atomic bitset allocator.
    ///
    /// On cache hit the existing address is reused. On miss a bit is claimed
    /// from `v4_set`, the domain→IP and IP→domain mappings are inserted, and
    /// the new address is returned. Pool is exhausted when all 2^16 bits are
    /// set.
    #[inline]
    pub fn respond_by_bitset(&self, dom: String) -> Result<Ipv4Addr> {
        // Fast path: domain already has a virtual IP
        if let Some(hit) = self.f_domain.get(&dom) {
            return Ok(hit.addr());
        }

        trace!("virtdns bitset: alloc {}", dom);

        let ip = self.alloc_bitset().ok_or_else(|| anyhow!("virtual IPv4 pool exhausted"))?;
        let v4a = self.ipv4a(ip);

        self.f_domain.insert(dom.clone(), DomainEntry::BitSet(v4a));
        self.f_ip.insert(
            v4a,
            IPKeyEntry {
                domain: RoutingDecision::HostOverProxy(dom),
                lifetime: None,
            },
        );

        Ok(ip)
    }

    #[inline]
    pub fn receive_query(&self, data: &[u8]) -> Result<Vec<u8>> {
        let message = parse_data_to_dns_message(data, false)?;
        let query = message.queries().get(0).ok_or(anyhow!("DnsRequest no query body"))?;
        let qname = query.name().to_string();
        let qtype = query.query_type();
        if matches!(qtype, RecordType::AAAA) || self.aaaa_only {
            // AAAA: deterministic hash-based IPv6 — no allocation needed, O(1)
            let ip = self.domain_to_ipv6(&qname);
            let ipa = self.ipv6a(ip);
            if self.ip6.get(&ipa).is_none() {
                self.ip6.insert(ipa, RoutingDecision::HostOverProxy(qname.clone()));
            }
            let message = build_dns_response(message, &qname, ip.into(), 5)?;
            Ok(message.to_vec()?)
        } else {
            match qtype {
                RecordType::A => {
                    // A: bitset-allocated virtual IPv4
                    let ip = self.respond_by_bitset(qname.clone())?;
                    let message = build_dns_response(message, &qname, ip.into(), 5)?;
                    Ok(message.to_vec()?)
                }
                _ => {
                    let ip = self.respond_by_bitset(qname.clone())?;
                    let message = build_dns_response(message, &qname, ip.into(), 5)?;
                    Ok(message.to_vec()?)
                }
            }
        }
    }
    #[inline]
    pub fn preprocess(&self, addr: SocketAddr) -> VDNSRES {
        match addr {
            SocketAddr::V4(v4) => {
                let ip = v4.ip().to_owned();
                let v4a = self.ipv4a(ip);

                // Fast path: check range first to avoid map lookup for non-virtual IPs
                if !self.range.contains(&ip.into()) {
                    return VDNSRES::NormalProxying;
                }

                // Lookup in map
                if let Some(IPKeyEntry { domain, .. }) = self.f_ip.get(&v4a) {
                    VDNSRES::Opine(domain)
                } else {
                    warn!("virtdns: address with no associated domain, {}", &v4);
                    VDNSRES::ERR
                }
            }
            SocketAddr::V6(v6) => {
                let ip = v6.ip().to_owned();

                // Fast path: check subnet first
                if !self.subnet6.contains(ip) {
                    return VDNSRES::NormalProxying;
                }

                let v6a = self.ipv6a(ip);
                if let Some(h) = self.ip6.get(&v6a) {
                    VDNSRES::Opine(h)
                } else {
                    warn!("VirtDNSv6, entry not found");
                    VDNSRES::ERR
                }
            }
        }
    }
    pub fn ipv4a(&self, ip: Ipv4Addr) -> Ipv4A {
        Ipv4A::new(ip, self.alloc_v4.interval.host)
    }
    pub fn ipv6a(&self, ip: Ipv6Addr) -> Ipv6A {
        Ipv6A::new(ip, 128 - 7)
    }
    pub fn pin(&self, v4: Option<Ipv4Addr>, dom: String, tun: RoutingDecision) -> Result<()> {
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
                lock: self.alloc_v4.pool.clone().get_rc(),
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
