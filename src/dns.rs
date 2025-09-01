use anyhow::{anyhow, bail};
use concurrent_map::{ConcurrentMap, Maximum, Minimum};
use crossbeam::queue::{ArrayQueue, SegQueue};
use futures::{FutureExt, SinkExt, StreamExt};
use id_alloc::lock_alloc::Alloc;
use id_alloc::opool::RcGuard;
use tracing::{info, trace, warn};
use quick_cache::sync::Cache;
use quick_cache::{DefaultHashBuilder, Lifecycle, UnitWeighter};
use serde::{Deserialize, Serialize};
use socks5_impl::protocol::Address;
use std::collections::{BTreeSet, HashMap, HashSet};
use std::future::Future;
use std::hash::{Hash, RandomState};
use std::num::NonZeroUsize;
use std::pin::Pin;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::task::{ready, Context, Poll};
use std::time::{Duration, Instant};
use std::{net::IpAddr, str::FromStr};
use tokio::sync::RwLock;
use tokio::time::sleep;
use trust_dns_proto::op::MessageType;
use trust_dns_proto::{
    op::{Message, ResponseCode},
    rr::{record_type::RecordType, Name, RData, Record},
};

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

use bimap::BiMap;
use id_alloc::{lock_alloc, IDAlloc, IPOps, Ipv4A};
use id_alloc::{Ipv4Network, NetRange};
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::ops::{Deref, RangeInclusive};

#[derive(Serialize, Deserialize, Debug)]
pub struct DNSState<R: Hash + Eq, L: Hash + Eq> {
    pub map: HashMap<R, L>,
    pub subnet: Ipv4Network,
}

#[derive(Debug)]
pub enum VDNSRES {
    Addr(Address),
    ERR,
}

pub struct VirtDNSAsync {
    /// User designated name mappings
    pub designated: BiMap<Ipv4Addr, String>,
    pub subnet: Ipv4Network,
    pub range: RangeInclusive<Ipv4A>,
    pub handle: VirtDNSHandle,
}

type PoolEntry = Arc<RcGuard<lock_alloc::Allocator<Ipv4A>, Ipv4A>>;
type EvictedQ = Arc<SegQueue<Ipv4A>>;

#[derive(Clone)]
pub struct VirtDNSHandle {
    f_ip: ConcurrentMap<Ipv4A, IPKeyEntry>,
    f_domain: Arc<Cache<String, PoolEntry, UnitWeighter, DefaultHashBuilder, IPEviction>>,
    alloc: lock_alloc::Alloc<Ipv4A>,
    range: RangeInclusive<Ipv4A>,
    evicted: EvictedQ,
}

#[derive(Clone)]
/// Eviction is depedent on LRU(domain -> IP)
struct IPEviction {
    evicted: EvictedQ,
}

impl Lifecycle<String, PoolEntry> for IPEviction {
    type RequestState = ();

    fn begin_request(&self) -> Self::RequestState {}
    fn on_evict(&self, state: &mut Self::RequestState, key: String, val: PoolEntry) {
        info!("Evict {} -> {:?}", key, val);
        self.evicted.push(**val);
    }
}

// when a client queries DNS, an IP is allocated to a domain
// the clients will believe the IP associates with the domain for indefinite time
// there is no way to determine when the clients stop believing this
// ofc there is usually an expiry time about DNS
// here we just bound it with LRU, to prevent exhaustion of IP pool

#[derive(Clone)]
struct IPKeyEntry {
    domain: String,
    lifetime: PoolEntry,
}

const LRU: usize = 4096;

// DNS metrics
const LRU_IP_HITS: AtomicUsize = AtomicUsize::new(0);
const DOMAIN_HITS: AtomicUsize = AtomicUsize::new(0);
const IP_HITS: AtomicUsize = AtomicUsize::new(0);

impl VirtDNSAsync {
    pub fn default(cap: usize) -> Result<Self> {
        let subnet: Ipv4Network = "198.18.0.0/16".parse()?;
        let range = subnet.range(0);
        let concmap: ConcurrentMap<Ipv4A, IPKeyEntry> = Default::default();
        let ev: Arc<SegQueue<Ipv4A>> = Default::default();
        Ok(Self {
            designated: Default::default(),
            range: range.clone(),
            handle: VirtDNSHandle {
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
                    cap,
                ),
                range,
            },
            subnet,
        })
    }
    pub fn from_state(cap: usize, sta: DNSState<String, Ipv4Addr>) -> Result<Self> {
        info!("Resume DNS state. {} records", sta.map.len());
        let range = sta.subnet.range(0);
        let concmap: ConcurrentMap<Ipv4A, IPKeyEntry> = Default::default();
        let ev: Arc<SegQueue<Ipv4A>> = Default::default();
        Ok(Self {
            designated: Default::default(),
            range: range.clone(),
            subnet: sta.subnet,
            handle: VirtDNSHandle {
                f_domain: Arc::new(Cache::with(
                    LRU,
                    LRU as u64,
                    UnitWeighter,
                    DefaultHashBuilder::default(),
                    IPEviction { evicted: ev.clone() },
                )),
                f_ip: concmap,
                evicted: ev,
                alloc: Alloc::init(
                    Ipv4A {
                        addr: sta.subnet.ip(),
                        host: 16,
                    },
                    cap,
                ),
                range,
            },
        })
    }
    pub fn to_state(&self) -> DNSState<String, Ipv4Addr> {
        DNSState {
            map: self.handle.f_ip.iter().map(|(ip, dom)| (dom.domain, ip.addr)).collect(),
            subnet: self.subnet.clone(),
        }
    }
}

impl VirtDNSHandle {
    pub async fn periodic_report(self) {
        // tokio::spawn(async move {
        //     loop {
        //         tokio::time::sleep(Duration::from_secs(1)).await;
        //         info!("LRU size = {}, DNS map = {}", self.lru_domains.len(), self.domains.len());
        //     }
        // });
    }
    pub fn alloc(&self, dom: String) -> Result<Ipv4Addr> {
        trace!("virtdns: alloc {}", dom);
        self.apply_evictions();
        IP_HITS.fetch_add(1, Ordering::SeqCst);
        if let Some(hit) = self.f_domain.get(&dom) {
            let addr = hit.addr;
            Ok(addr)
        } else {
            let own = Arc::new(self.alloc.pool.clone().get_rc());
            trace!("got object from pool");
            let addr = own.addr;
            self.f_ip.insert(
                **own,
                IPKeyEntry {
                    domain: dom.clone(),
                    lifetime: own.clone(),
                },
            );
            self.f_domain.insert(dom, own);
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
        let ip = self.alloc(qname.clone())?;
        let message = build_dns_response(message, &qname, ip.into(), 5)?;
        Ok(message.to_vec()?)
    }
    pub fn process(&self, addr: SocketAddr) -> VDNSRES {
        trace!("virtdns: resolve {}", addr);
        match addr {
            SocketAddr::V4(v4) => {
                // this takes priority
                if self.range.contains(&v4.ip().to_owned().into()) {
                    let dns_hit = || DOMAIN_HITS.fetch_add(1, Ordering::SeqCst);
                    // Exclusive range for Virt DNS
                    let v4a = Ipv4A::new(*v4.ip(), self.alloc.interval.host);

                    if let Some(IPKeyEntry { domain, lifetime }) = self.f_ip.get(&v4a) {
                        dns_hit();
                        VDNSRES::Addr(Address::DomainAddress(domain, v4.port()))
                    } else {
                        warn!("virtdns: address with no associated domain, {}", &v4);
                        VDNSRES::ERR
                    }

                    // Reset
                } else {
                    VDNSRES::Addr(Address::SocketAddress(v4.into()))
                }
            }
            k => VDNSRES::Addr(k.into()),
        }
    }
}
