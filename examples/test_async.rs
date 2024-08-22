use std::net::SocketAddr;
use std::net::SocketAddrV4;
use std::time::Duration;

use anyhow::Result;
use id_alloc::Ipv4Network;
use log::info;
use rand::Rng;
use tokio::time::sleep;
use tun2socks5::aok;
use tun2socks5::dns::*;

#[allow(unreachable_code)]
#[tokio::main]
async fn main() -> Result<()> {
    println!("begin");
    let vdns = VirtDNSAsync::default(10)?;
    let hd = vdns.handle.clone();
    let subnet: Ipv4Network = "198.18.0.0/16".parse()?;
    tokio::spawn(vdns.serve());
    let k = tokio::join!(
        async {
            let mut rng = rand::thread_rng();
            loop {
                let n = rng.gen_range(0..1024);
                let al = hd.alloc(n.to_string()).await?;
                println!("alloc {}", al);
                let slp = rng.gen_range(0..128);
                let slp = Duration::from_millis(slp);
                sleep(slp).await;
            }
            aok!(())
        },
        async {
            let mut rng = rand::thread_rng();
            loop {
                let n = rng.gen_range(0..1024);
                let ip = SocketAddr::V4(SocketAddrV4::new(subnet.nth(n).unwrap(), 0));
                let x = hd.process(ip).await;
                println!("{} -> {:?}", &ip, x);
                let slp = rng.gen_range(0..128);
                let slp = Duration::from_millis(slp);
                sleep(slp).await;
            }
            aok!(())
        }
    );

    dbg!(k);

    aok!(())
}
