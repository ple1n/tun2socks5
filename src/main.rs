use clap::Parser;
use tun2socks5::{config_restore, config_settings, main_entry, Args, TUN_GATEWAY, TUN_IPV4, TUN_NETMASK};

// const MTU: u16 = 1500;
const MTU: u16 = u16::MAX;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    dotenvy::dotenv().ok();
    let args = Args::parse();

    // let tun_name = args.tun.clone();
    // let bypass_ips = args.bypass.clone();

    // let default = format!("{}={:?}", module_path!(), args.verbosity);
    // env_logger::Builder::from_env(env_logger::Env::default().default_filter_or(default)).init();

    // let mut config = tun::Configuration::default();
    // config.address(TUN_IPV4).netmask(TUN_NETMASK).mtu(MTU as i32).up();
    // config.destination(TUN_GATEWAY).name(&tun_name);

    // #[cfg(target_os = "linux")]
    // config.platform(|config| {
    //     config.packet_information(true);
    //     config.apply_settings(false);
    // });

    // #[cfg(target_os = "windows")]
    // config.platform(|config| {
    //     config.initialize(Some(12324323423423434234_u128));
    // });

    // #[allow(unused_mut, unused_assignments)]
    // let mut setup = true;

    // #[cfg(target_os = "linux")]
    // {
    //     setup = args.setup;
    //     if setup {
    //         config_settings(&bypass_ips, &tun_name, Some(args.dns_addr))?;
    //     }
    // }

    // let device = tun::create_as_async(&config)?;

    // #[cfg(any(target_os = "windows", target_os = "macos"))]
    // if setup {
    //     config_settings(&bypass_ips, &tun_name, Some(args.dns_addr))?;
    // }

    // let (tx, rx) = tokio::sync::mpsc::channel::<()>(1);
    // ctrlc2::set_async_handler(async move {
    //     tx.send(()).await.expect("Send exit signal");
    // })
    // .await;

    // if let Err(err) = main_entry(device, MTU, true, args, rx).await {
    //     log::trace!("main_entry error {}", err);
    // }

    // #[cfg(any(target_os = "linux", target_os = "windows", target_os = "macos"))]
    // if setup {
    //     config_restore(&bypass_ips, &tun_name)?;
    // }

    Ok(())
}
