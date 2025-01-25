use anyhow::{anyhow, bail};
use futures::{FutureExt, SinkExt, StreamExt};
use log::{info, trace};
use serde::{Deserialize, Serialize};
use socks5_impl::protocol::Address;
use std::collections::{HashMap, HashSet};
use std::future::Future;
use std::hash::Hash;
use std::num::NonZeroUsize;
use std::pin::Pin;
use std::task::{ready, Context, Poll};
use std::time::Duration;
use std::{net::IpAddr, str::FromStr};
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

use crate::aok;
use crate::error::Result;
use crate::lru::BijectiveLRU;
use bimap::BiMap;
use id_alloc::{IDAlloc, Ipv4A};
use id_alloc::{Ipv4Network, NetRange};
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::ops::RangeInclusive;

pub struct VirtDNS {
    /// IP -> Domain when getting TCP packets
    /// Domain -> IP when getting DNS
    pub map: BijectiveLRU<Ipv4Addr, String>,
    /// User designated name mappings
    pub designated: BiMap<Ipv4Addr, String>,
    pub subnet: Ipv4Network,
    pub range: RangeInclusive<Ipv4A>,
    pub alloc: IDAlloc<Ipv4A>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct DNSState<R: Hash + Eq, L: Hash + Eq> {
    pub map: HashMap<R, L>,
    pub subnet: Ipv4Network,
    pub alloc: IDAlloc<Ipv4A>,
}

impl VirtDNS {
    pub fn default(cap: usize) -> Result<Self> {
        let subnet: Ipv4Network = "198.18.0.0/16".parse()?;
        Ok(VirtDNS {
            map: BijectiveLRU::new(NonZeroUsize::try_from(cap)?),
            designated: Default::default(),
            range: subnet.range(0),
            alloc: Default::default(),
            subnet,
        })
    }
    pub fn from_state(cap: usize, sta: DNSState<String, Ipv4Addr>) -> Result<Self> {
        log::info!("Resume DNS state. {} records", sta.map.len());
        let map = BijectiveLRU::from_map(NonZeroUsize::try_from(cap)?, sta.map);
        Ok(Self {
            map,
            designated: Default::default(),
            range: sta.subnet.range(0),
            subnet: sta.subnet,
            alloc: sta.alloc,
        })
    }
    pub fn to_state(self) -> DNSState<String, Ipv4Addr> {
        DNSState {
            map: self.map.map,
            subnet: self.subnet,
            alloc: self.alloc,
        }
    }
    pub fn alloc(&mut self, dom: &str) -> Result<&Ipv4Addr> {
        if self.map.rcontains(dom) {
        } else {
            let v4 = if let Some(addr) = self.designated.get_by_right(dom) {
                addr.to_owned()
            } else {
                self.alloc.alloc_or(&self.range)?.addr
            };
            let freed = self.map.push(v4, dom.to_owned());
            for ip in freed {
                if let Some((ip, domain)) = ip {
                    self.alloc.unset(ip.into())
                }
            }
        }
        Ok(self.map.rget(dom).unwrap())
    }
    pub fn receive_query(&mut self, data: &[u8]) -> Result<Vec<u8>> {
        let message = parse_data_to_dns_message(data, false)?;
        let qname = extract_domain_from_dns_message(&message)?;
        log::info!("VirtDNS {}", qname);
        let ip = self.alloc(&qname)?;
        let message = build_dns_response(message, &qname, ip.to_owned().into(), 5)?;
        Ok(message.to_vec()?)
    }
    pub fn process(&mut self, addr: SocketAddr) -> VDNSRES {
        match addr {
            SocketAddr::V4(v4) => {
                // this takes priority
                if let Some(desig) = self.designated.get_by_left(&v4.ip()) {
                    VDNSRES::Addr(Address::DomainAddress(desig.to_owned(), v4.port()))
                } else {
                    if self.range.contains(&v4.ip().to_owned().into()) {
                        // Exclusive range for Virt DNS
                        if let Some(ad) = self.map.lget(v4.ip()) {
                            VDNSRES::Addr(Address::DomainAddress(ad.to_string(), v4.port()))
                        } else {
                            VDNSRES::ERR
                        }
                        // Reset
                    } else {
                        VDNSRES::Addr(Address::SocketAddress(v4.into()))
                    }
                }
            }
            k => VDNSRES::Addr(k.into()),
        }
    }
}

#[derive(Debug)]
pub enum VDNSRES {
    Addr(Address),
    ERR,
}

use futures::channel::oneshot;
use tokio::sync::mpsc::{unbounded_channel, UnboundedReceiver, UnboundedSender};

type DNSStateTy = DNSState<String, Ipv4Addr>;
pub struct VirtDNSAsync {
    /// IP -> Domain when getting TCP packets
    /// Domain -> IP when getting DNS
    pub map: BijectiveLRU<Ipv4Addr, String>,
    /// User designated name mappings
    pub designated: BiMap<Ipv4Addr, String>,
    pub subnet: Ipv4Network,
    pub range: RangeInclusive<Ipv4A>,
    pub alloc: IDAlloc<Ipv4A>,
    reqs_domain: UnboundedReceiver<(String, oneshot::Sender<Result<Ipv4Addr>>)>,
    reqs_addr: UnboundedReceiver<(SocketAddr, oneshot::Sender<VDNSRES>)>,
    reqs_state: UnboundedReceiver<oneshot::Sender<DNSState<String, Ipv4Addr>>>,
    pub handle: VirtDNSHandle,
}

#[derive(Clone)]
pub struct VirtDNSHandle {
    sx_domain: UnboundedSender<(String, oneshot::Sender<Result<Ipv4Addr>>)>,
    sx_addr: UnboundedSender<(SocketAddr, oneshot::Sender<VDNSRES>)>,
    sx_state: UnboundedSender<oneshot::Sender<DNSState<String, Ipv4Addr>>>,
}

impl VirtDNSAsync {
    pub fn default(cap: usize) -> Result<Self> {
        let subnet: Ipv4Network = "198.18.0.0/16".parse()?;
        let (sx_domain, reqs_domain) = unbounded_channel();
        let (sx_addr, reqs_addr) = unbounded_channel();
        let (sx_state, reqs_state) = unbounded_channel();

        Ok(Self {
            map: BijectiveLRU::new(NonZeroUsize::try_from(cap)?),
            designated: Default::default(),
            range: subnet.range(0),
            alloc: Default::default(),
            subnet,
            reqs_addr,
            reqs_state,
            reqs_domain,
            handle: VirtDNSHandle {
                sx_addr,
                sx_domain,
                sx_state,
            },
        })
    }
    pub fn from_state(cap: usize, sta: DNSState<String, Ipv4Addr>) -> Result<Self> {
        log::info!("Resume DNS state. {} records", sta.map.len());
        let (sx_domain, reqs_domain) = unbounded_channel();
        let (sx_addr, reqs_addr) = unbounded_channel();
        let (sx_state, reqs_state) = unbounded_channel();

        let map = BijectiveLRU::from_map(NonZeroUsize::try_from(cap)?, sta.map);
        Ok(Self {
            map,
            designated: Default::default(),
            range: sta.subnet.range(0),
            subnet: sta.subnet,
            alloc: sta.alloc,

            reqs_addr,
            reqs_state,
            reqs_domain,
            handle: VirtDNSHandle {
                sx_addr,
                sx_domain,
                sx_state,
            },
        })
    }
    pub fn to_state(&self) -> DNSState<String, Ipv4Addr> {
        DNSState {
            map: self.map.map.clone(),
            subnet: self.subnet.clone(),
            alloc: self.alloc.clone(),
        }
    }
    pub async fn serve(mut self) {
        loop {
            futures::select! {
                rx = self.reqs_domain.recv().fuse() => {
                    let (domain, sx) = rx.unwrap();
                    let mut process = |dom: &str| {
                        if self.map.rcontains(dom) {
                        } else {
                            let v4 = if let Some(addr) = self.designated.get_by_right(dom) {
                                addr.to_owned()
                            } else {
                                self.alloc.alloc_or(&self.range)?.addr
                            };
                            let freed = self.map.push(v4, dom.to_owned());
                            for ip in freed {
                                if let Some((ip, domain)) = ip {
                                    self.alloc.unset(ip.into())
                                }
                            }
                        }
                        Result::Ok(self.map.rget(dom).unwrap().clone())
                    };
                    sx.send(process(&domain).map_err(anyhow::Error::from)).expect("send failed");
                }
                rx = self.reqs_addr.recv().fuse() => {
                    let (addr, sx) = rx.unwrap();
                    let back = match addr {
                        SocketAddr::V4(v4) => {
                            // this takes priority
                            if let Some(desig) = self.designated.get_by_left(&v4.ip()) {
                                VDNSRES::Addr(Address::DomainAddress(desig.to_owned(), v4.port()))
                            } else {
                                if self.range.contains(&v4.ip().to_owned().into()) {
                                    // Exclusive range for Virt DNS
                                    if let Some(ad) = self.map.lget(v4.ip()) {
                                        VDNSRES::Addr(Address::DomainAddress(ad.to_string(), v4.port()))
                                    } else {
                                        VDNSRES::ERR
                                    }
                                    // Reset
                                } else {
                                    VDNSRES::Addr(Address::SocketAddress(v4.into()))
                                }
                            }
                        }
                        k => VDNSRES::Addr(k.into()),
                    };
                    sx.send(back).expect("send failed");
                },
                rx = self.reqs_state.recv().fuse() => {
                    let sx = rx.unwrap();
                    sx.send(self.to_state()).expect("send failed");

                }
            }
        }
    }
}

impl VirtDNSHandle {
    pub async fn alloc(&self, dom: String) -> Result<Ipv4Addr> {
        let (sx, rx) = oneshot::channel();
        trace!("virtdns: alloc {}", dom);
        self.sx_domain.send((dom, sx))?;
        let k = rx.await??;
        Ok(k)
    }
    pub async fn receive_query(&self, data: &[u8]) -> Result<Vec<u8>> {
        let message = parse_data_to_dns_message(data, false)?;
        let qname = extract_domain_from_dns_message(&message)?;
        info!("VirtDNS {}", qname);
        let ip = self.alloc(qname.clone()).await?;
        let message = build_dns_response(message, &qname, ip.into(), 5)?;
        Ok(message.to_vec()?)
    }
    pub async fn process(&self, addr: SocketAddr) -> VDNSRES {
        let (sx, rx) = oneshot::channel();
        info!("virtdns: resolve {}", addr);
        self.sx_addr.send((addr, sx)).unwrap();
        rx.await.unwrap()
    }
    pub async fn to_state(&self) -> DNSStateTy {
        let (sx, rx) = oneshot::channel();
        self.sx_state.send(sx).unwrap();
        rx.await.unwrap()
    }
}
