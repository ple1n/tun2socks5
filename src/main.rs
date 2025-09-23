use std::sync::Arc;

use clap::Parser;
use futures::channel::mpsc::unbounded;
use ipstack::TUNDev;
use tracing::info;
use tracing::trace;
use tun2socks5::{config_restore, config_settings, main_entry, ArgMode, Args, IArgs, TUN_GATEWAY, TUN_IPV4, TUN_NETMASK};

// const MTU: u16 = 1500;
const MTU: u16 = u16::MAX;

use tun_rs::{AsyncDevice, DeviceBuilder, ToIpv4Address};

fn main() -> anyhow::Result<()> {
    let rt = tokio::runtime::Builder::new_multi_thread().worker_threads(12).build().unwrap();
    rt.block_on(main_fn())?;

    anyhow::Result::Ok(())
}

async fn main_fn() -> anyhow::Result<()> {
    dotenvy::dotenv().ok();
    let args = Args::parse();
    let iargs: IArgs = match args.args {
        ArgMode::File { path } => {
            info!("Reading from {:?}", &path);
            let mut f = std::fs::File::open(path)?;
            let iargs: IArgs = serde_json::from_reader(&mut f)?;
            // Be aware of conflicts
            iargs
        }
        ArgMode::Args(args) => args,
    };

    let tun_name = args.tun.clone();
    let bypass_ips = iargs.bypass.clone();

    let default = format!("{}={:?}", module_path!(), args.verbosity);
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or(default)).init();

    let mut dev_builder = DeviceBuilder::new()
        .ipv4(TUN_IPV4, TUN_NETMASK.ipv4().unwrap(), Some(TUN_GATEWAY))
        .mtu(MTU);

    #[cfg(target_os = "linux")]
    {
        dev_builder = dev_builder.packet_information(true).multi_queue(true);
    }

    let device: TUNDev = Arc::new(dev_builder.build_async()?);

    #[allow(unused_mut, unused_assignments)]
    let mut setup = true;

    #[cfg(target_os = "linux")]
    {
        setup = args.setup;
        if setup {
            config_settings(&bypass_ips, &tun_name, Some(iargs.dns_addr))?;
        }
    }

    #[cfg(any(target_os = "windows", target_os = "macos"))]
    if setup {
        config_settings(&bypass_ips, &tun_name, Some(args.dns_addr))?;
    }

    let (tx, rx) = tokio::sync::mpsc::channel::<()>(1);
    let t2 = tx.clone();
    ctrlc2::set_async_handler(async move {
        t2.send(()).await.expect("Send exit signal");
    })
    .await;

    let (tunsx, tunrx) = unbounded();
    if let Err(err) = main_entry(device, MTU, true, iargs, tunrx).await {
        trace!("main_entry error {}", err);
    }

    #[cfg(any(target_os = "linux", target_os = "windows", target_os = "macos"))]
    if setup {
        config_restore(&bypass_ips, &tun_name)?;
    }

    Ok(())
}
