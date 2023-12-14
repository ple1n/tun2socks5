use std::net::{IpAddr, Ipv4Addr};

use anyhow::bail;
use crate::Result;

pub const TUN_IPV4: IpAddr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 33));
pub const TUN_NETMASK: IpAddr = IpAddr::V4(Ipv4Addr::new(255, 255, 255, 0));
pub const TUN_GATEWAY: IpAddr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
pub const TUN_DNS: IpAddr = IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8));

pub static mut DEFAULT_GATEWAY: Option<IpAddr> = None;

#[cfg(windows)]
pub fn config_settings(bypass_ips: &[IpAddr], tun_name: &str, dns_addr: Option<IpAddr>) -> Result<()> {
    // 1. Setup the adapter's DNS
    // command: `netsh interface ip set dns "utun3" static 8.8.8.8`
    let dns_addr = dns_addr.unwrap_or(TUN_DNS);
    let tun_name = format!("\"{}\"", tun_name);
    let args = &["interface", "ip", "set", "dns", &tun_name, "static", &dns_addr.to_string()];
    run_command("netsh", args)?;
    log::info!("netsh {:?}", args);

    // 2. Route all traffic to the adapter, here the destination is adapter's gateway
    // command: `route add 0.0.0.0 mask 0.0.0.0 10.1.0.1 metric 6`
    let unspecified = Ipv4Addr::UNSPECIFIED.to_string();
    let gateway = TUN_GATEWAY.to_string();
    let args = &["add", &unspecified, "mask", &unspecified, &gateway, "metric", "6"];
    run_command("route", args)?;
    log::info!("route {:?}", args);

    let old_gateway = get_default_gateway()?;
    unsafe {
        DEFAULT_GATEWAY = Some(old_gateway);
    }

    // 3. route the bypass ip to the old gateway
    // command: `route add bypass_ip old_gateway metric 1`
    for bypass_ip in bypass_ips {
        let args = &["add", &bypass_ip.to_string(), &old_gateway.to_string(), "metric", "1"];
        run_command("route", args)?;
        log::info!("route {:?}", args);
    }

    Ok(())
}

#[cfg(target_os = "linux")]
pub fn config_settings(bypass_ips: &[IpAddr], tun_name: &str, _dns_addr: Option<IpAddr>) -> Result<()> {
    // sudo ip tuntap add name tun0 mode tun
    let args = &["tuntap", "add", "name", tun_name, "mode", "tun"];
    run_command("ip", args)?;

    // sudo ip link set tun0 up
    let args = &["link", "set", tun_name, "up"];
    run_command("ip", args)?;

    // sudo ip route add "${bypass_ip}" $(ip route | grep '^default' | cut -d ' ' -f 2-)
    let args = &["-c", "ip route | grep '^default' | cut -d ' ' -f 2-"];
    let out = run_command("sh", args)?;
    let stdout = String::from_utf8_lossy(&out).into_owned();
    for bypass_ip in bypass_ips {
        let cmd = format!("ip route add {} {}", bypass_ip, stdout.trim());
        let args = &["-c", &cmd];
        if let Err(err) = run_command("sh", args) {
            log::trace!("run_command {}", err);
        }
    }

    // sudo ip route add 128.0.0.0/1 dev tun0
    let args = &["route", "add", "128.0.0.0/1", "dev", tun_name];
    run_command("ip", args)?;

    // sudo ip route add 0.0.0.0/1 dev tun0
    let args = &["route", "add", "0.0.0.0/1", "dev", tun_name];
    run_command("ip", args)?;

    // sudo ip route add ::/1 dev tun0
    let args = &["route", "add", "::/1", "dev", tun_name];
    run_command("ip", args)?;

    // sudo ip route add 8000::/1 dev tun0
    let args = &["route", "add", "8000::/1", "dev", tun_name];
    run_command("ip", args)?;

    // sudo sh -c "echo nameserver 198.18.0.1 > /etc/resolv.conf"
    let file = std::fs::OpenOptions::new().write(true).truncate(true).open("/etc/resolv.conf")?;
    let mut writer = std::io::BufWriter::new(file);
    use std::io::Write;
    writeln!(writer, "nameserver 198.18.0.1")?;

    Ok(())
}

#[cfg(target_os = "macos")]
pub fn config_settings(bypass_ips: &[IpAddr], tun_name: &str, _dns_addr: Option<IpAddr>) -> Result<()> {
    // 0. Save the old gateway
    let old_gateway = get_default_gateway()?;
    unsafe {
        DEFAULT_GATEWAY = Some(old_gateway);
    }
    let old_gateway = old_gateway.to_string();

    let unspecified = Ipv4Addr::UNSPECIFIED.to_string();

    // 1. Set up the address and netmask and gateway of the interface
    // Command: `sudo ifconfig tun_name 10.0.0.33 10.0.0.1 netmask 255.255.255.0`
    let tun_ip = TUN_IPV4.to_string();
    let tun_netmask = TUN_NETMASK.to_string();
    let tun_gateway = TUN_GATEWAY.to_string();
    let args = &[tun_name, &tun_ip, &tun_gateway, "netmask", &tun_netmask];
    run_command("ifconfig", args)?;

    // 2. Remove the default route
    // Command: `sudo route delete 0.0.0.0`
    let args = &["delete", &unspecified];
    run_command("route", args)?;

    // 3. Set the gateway `10.0.0.1` as the default route
    // Command: `sudo route add -net 0.0.0.0 10.0.0.1`
    let args = &["add", "-net", &unspecified, &tun_gateway];
    run_command("route", args)?;

    // 4. Route the bypass ip to the old gateway
    // Command: `sudo route add bypass_ip/32 old_gateway`
    for bypass_ip in bypass_ips {
        let args = &["add", &bypass_ip.to_string(), &old_gateway];
        run_command("route", args)?;
    }

    // 5. Set the DNS server to a reserved IP address
    // Command: `sudo sh -c "echo nameserver 198.18.0.1 > /etc/resolv.conf"`
    let file = std::fs::OpenOptions::new().write(true).truncate(true).open("/etc/resolv.conf")?;
    let mut writer = std::io::BufWriter::new(file);
    use std::io::Write;
    writeln!(writer, "nameserver 198.18.0.1\n")?;
    Ok(())
}

#[cfg(windows)]
pub fn config_restore(_bypass_ips: &[IpAddr], _tun_name: &str) -> Result<()> {
    if unsafe { DEFAULT_GATEWAY.is_none() } {
        return Ok(());
    }
    let err = std::io::Error::new(std::io::ErrorKind::Other, "No default gateway found");
    let old_gateway = unsafe { DEFAULT_GATEWAY.take() }.ok_or(err)?;
    let unspecified = Ipv4Addr::UNSPECIFIED.to_string();

    // 1. Remove current adapter's route
    // command: `route delete 0.0.0.0 mask 0.0.0.0`
    let args = &["delete", &unspecified, "mask", &unspecified];
    run_command("route", args)?;

    // 2. Add back the old gateway route
    // command: `route add 0.0.0.0 mask 0.0.0.0 old_gateway metric 200`
    let old_gateway = old_gateway.to_string();
    let args = &["add", &unspecified, "mask", &unspecified, &old_gateway, "metric", "200"];
    run_command("route", args)?;

    Ok(())
}

#[cfg(target_os = "linux")]
pub fn config_restore(bypass_ips: &[IpAddr], tun_name: &str) -> Result<()> {
    // sudo route del bypass_ip
    for bypass_ip in bypass_ips {
        let args = &["del", &bypass_ip.to_string()];
        run_command("route", args)?;
    }

    // sudo ip link del tun0
    let args = &["link", "del", tun_name];
    run_command("ip", args)?;

    // sudo systemctl restart systemd-resolved.service
    let args = &["restart", "systemd-resolved.service"];
    run_command("systemctl", args)?;

    Ok(())
}

#[cfg(target_os = "macos")]
pub fn config_restore(_bypass_ips: &[IpAddr], _tun_name: &str) -> Result<()> {
    if unsafe { DEFAULT_GATEWAY.is_none() } {
        return Ok(());
    }
    let err = std::io::Error::new(std::io::ErrorKind::Other, "No default gateway found");
    let old_gateway = unsafe { DEFAULT_GATEWAY.take() }.ok_or(err)?.to_string();
    let unspecified = Ipv4Addr::UNSPECIFIED.to_string();

    // 1. Remove current adapter's route
    // command: `sudo route delete 0.0.0.0`
    let args = &["delete", &unspecified];
    run_command("route", args)?;

    // 2. Add back the old gateway route
    // command: `sudo route add -net 0.0.0.0 old_gateway`
    let args = &["add", "-net", &unspecified, &old_gateway];
    run_command("route", args)?;

    // 3. Restore DNS server to the old gateway
    // command: `sudo sh -c "echo nameserver old_gateway > /etc/resolv.conf"`
    let file = std::fs::OpenOptions::new().write(true).truncate(true).open("/etc/resolv.conf")?;
    let mut writer = std::io::BufWriter::new(file);
    use std::io::Write;
    writeln!(writer, "nameserver {}\n", old_gateway)?;

    Ok(())
}

pub fn run_command(command: &str, args: &[&str]) -> crate::Result<Vec<u8>> {
    let out = std::process::Command::new(command).args(args).output()?;
    if !out.status.success() {
        let err = String::from_utf8_lossy(if out.stderr.is_empty() { &out.stdout } else { &out.stderr });
        let info = format!("{} failed with: \"{}\"", command, err);
        bail!(std::io::Error::new(std::io::ErrorKind::Other, info))
    }
    Ok(out.stdout)
}

#[cfg(windows)]
pub(crate) fn get_default_gateway() -> Result<IpAddr> {
    let args = &[
        "-Command",
        "Get-WmiObject -Class Win32_NetworkAdapterConfiguration -Filter IPEnabled=TRUE | ForEach-Object { $_.DefaultIPGateway }",
    ];
    let gateways = run_command("powershell", args)?;

    let stdout = String::from_utf8_lossy(&gateways).into_owned();
    let lines: Vec<&str> = stdout.lines().collect();

    let mut ipv4_gateway = None;
    let mut ipv6_gateway = None;

    for line in lines {
        if let Ok(ip) = <IpAddr as std::str::FromStr>::from_str(line) {
            match ip {
                IpAddr::V4(_) => {
                    ipv4_gateway = Some(ip);
                    break;
                }
                IpAddr::V6(_) => {
                    ipv6_gateway = Some(ip);
                }
            }
        }
    }

    let err = std::io::Error::new(std::io::ErrorKind::Other, "No default gateway found");
    ipv4_gateway.or(ipv6_gateway).ok_or(err)
}

#[cfg(target_os = "linux")]
#[allow(dead_code)]
pub(crate) fn get_default_gateway() -> Result<IpAddr> {
    // Command: sh -c "ip route | grep default | awk '{print $3}'"
    let args = &["-c", "ip route | grep default | awk '{print $3}'"];
    let out = run_command("sh", args)?;
    let stdout = String::from_utf8_lossy(&out).into_owned();
    let addr = <IpAddr as std::str::FromStr>::from_str(stdout.trim()).map_err(crate::Error::from)?;
    Ok(addr)
}

#[cfg(target_os = "macos")]
pub(crate) fn get_default_gateway() -> Result<IpAddr> {
    // Command: `netstat -rn | grep default | grep -E -o '[0-9\.]+' | head -n 1`
    let args = &["-c", "netstat -rn | grep default | grep -E -o '[0-9\\.]+' | head -n 1"];
    let out = run_command("sh", args)?;
    let stdout = String::from_utf8_lossy(&out).into_owned();
    let addr = <IpAddr as std::str::FromStr>::from_str(stdout.trim()).map_err(crate::Error::from)?;
    Ok(addr)
}
