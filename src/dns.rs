use anyhow::{anyhow, bail};
use concurrent_map::{ConcurrentMap, Maximum, Minimum};
use futures::{FutureExt, SinkExt, StreamExt};
use id_alloc::lock_alloc::Alloc;
use id_alloc::opool::RcGuard;
use log::{info, trace};
use quick_cache::sync::Cache;
use serde::{Deserialize, Serialize};
use socks5_impl::protocol::Address;
use std::collections::{BTreeSet, HashMap, HashSet};
use std::future::Future;
use std::hash::Hash;
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
use crate::lru::BijectiveLRU;
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

type CacheEntry = Arc<RcGuard<lock_alloc::Allocator<Ipv4A>, Ipv4A>>;
// type CacheEntry = Arc<RcGuard<lock_alloc::Allocator<Ipv4A>, Ipv4A>>;

#[derive(Clone)]
pub struct VirtDNSHandle {
    domains: ConcurrentMap<Ipv4A, IPKeyEntry>,
    lru: Arc<quick_cache::sync::Cache<Ipv4A, CacheEntry>>,
    lru_domains: Arc<quick_cache::sync::Cache<String, CacheEntry>>,
    alloc: lock_alloc::Alloc<Ipv4A>,
    range: RangeInclusive<Ipv4A>,
}

#[derive(Clone)]
struct IPKeyEntry {
    domain: String,
    lifetime: CacheEntry,
}

const LRU: usize = 128;

// DNS metrics
const LRU_IP_HITS: AtomicUsize = AtomicUsize::new(0);
const DOMAIN_HITS: AtomicUsize = AtomicUsize::new(0);
const IP_HITS: AtomicUsize = AtomicUsize::new(0);

impl VirtDNSAsync {
    pub fn default(cap: usize) -> Result<Self> {
        let subnet: Ipv4Network = "198.18.0.0/16".parse()?;
        let range = subnet.range(0);

        Ok(Self {
            designated: Default::default(),
            range: range.clone(),
            handle: VirtDNSHandle {
                domains: Default::default(),
                lru: Cache::new(LRU).into(),
                lru_domains: Cache::new(LRU).into(),
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
        log::info!("Resume DNS state. {} records", sta.map.len());
        let range = sta.subnet.range(0);
        Ok(Self {
            designated: Default::default(),
            range: range.clone(),
            subnet: sta.subnet,
            handle: VirtDNSHandle {
                lru: Cache::new(LRU).into(),
                lru_domains: Cache::new(LRU).into(),
                domains: Default::default(),
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
            map: self.handle.domains.iter().map(|(ip, dom)| (dom.domain, ip.addr)).collect(),
            subnet: self.subnet.clone(),
        }
    }
}

impl VirtDNSHandle {
    pub async fn periodic_report(self) {
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_secs(1)).await;
                log::info!("LRU size = {}, DNS map = {}", self.lru.len(), self.domains.len());
            }
        });
    }
    pub fn alloc(&self, dom: String) -> Result<Ipv4Addr> {
        trace!("virtdns: alloc {}", dom);
        IP_HITS.fetch_add(1, Ordering::SeqCst);
        if let Some(hit) = self.lru_domains.get(&dom) {
            let addr = hit.addr;
            Ok(addr)
        } else {
            let ip = Arc::new(self.alloc.pool.clone().get_rc());
            let addr = ip.addr;
            self.domains.insert(
                **ip,
                IPKeyEntry {
                    domain: dom.clone(),
                    lifetime: ip.clone(),
                },
            );
            self.lru_domains.insert(dom, ip);
            Ok(addr)
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
                    // visit cache first
                    let g = self.lru.get(&v4a);
                    if let Some(cached) = g {
                        dns_hit();
                        LRU_IP_HITS.fetch_add(1, Ordering::SeqCst);
                        let addr = cached.addr;
                        VDNSRES::Addr(Address::DomainAddress(addr.to_string(), v4.port()))
                    } else {
                        // not cached
                        if let Some(IPKeyEntry { domain, lifetime }) = self.domains.get(&v4a) {
                            self.lru.insert(v4a, lifetime);
                            dns_hit();
                            VDNSRES::Addr(Address::DomainAddress(domain, v4.port()))
                        } else {
                            VDNSRES::ERR
                        }
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
