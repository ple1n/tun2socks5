use anyhow::{anyhow, bail};
use socks5_impl::protocol::Address;
use std::num::NonZeroUsize;
use std::{net::IpAddr, str::FromStr};
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
use id_alloc::{IDAlloc, Ipv4A};
use id_alloc::{Ipv4Network, NetRange};
use std::net::{Ipv4Addr, SocketAddr};
use std::ops::RangeInclusive;

pub struct VirtDNS {
    /// IP -> Domain when getting TCP packets
    /// Domain -> IP when getting DNS
    pub map: BijectiveLRU<Ipv4Addr, String>,
    pub baseaddr: Ipv4Addr,
    pub dom: RangeInclusive<Ipv4A>,
    pub tree: IDAlloc<Ipv4A>,
}

impl VirtDNS {
    pub fn default(cap: usize) -> Result<Self> {
        let baseaddr = "198.18.0.0".parse()?;
        Ok(VirtDNS {
            map: BijectiveLRU::new(NonZeroUsize::try_from(cap)?),
            tree: Default::default(),
            baseaddr,
            dom: Ipv4Network::new(baseaddr, 16).unwrap().range(0),
        })
    }
    pub fn alloc(&mut self, dom: &str) -> Result<&Ipv4Addr> {
        if self.map.rcontains(dom) {
        } else {
            let v4 = self.tree.alloc_or(&self.dom)?;
            let freed = self.map.push(v4.addr.into(), dom.to_owned());
            for ip in freed {
                if let Some((ip, domain)) = ip {
                    self.tree.unset(ip.into())
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
                if self.dom.contains(&v4.ip().to_owned().into()) {
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
            k => VDNSRES::Addr(k.into()),
        }
    }
}

pub enum VDNSRES {
    Addr(Address),
    ERR,
}
