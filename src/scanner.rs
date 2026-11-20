use std::collections::HashSet;
use std::net::Ipv4Addr;
use std::time::Duration;

use anyhow::{Result, anyhow};
use ipnetwork::Ipv4Network;
use log::{info, warn};
use pnet::datalink::{self, Channel, NetworkInterface};
use pnet::packet::Packet;
use pnet::packet::arp::{ArpHardwareTypes, ArpOperations, ArpPacket, MutableArpPacket};
use pnet::packet::ethernet::{EtherTypes, EthernetPacket, MutableEthernetPacket};
use pnet::util::MacAddr;

use crate::models::ArpResult;

pub fn find_default_interface() -> Result<NetworkInterface> {
    let interfaces = datalink::interfaces();
    interfaces
        .into_iter()
        .filter(|iface| {
            !iface.is_loopback()
                && iface.is_up()
                && iface.mac.is_some()
                && iface
                    .ips
                    .iter()
                    .any(|ip| matches!(ip, ipnetwork::IpNetwork::V4(_)))
        })
        .max_by_key(|iface| iface.ips.len())
        .ok_or_else(|| anyhow!("No suitable network interface found"))
}

pub fn get_interface_subnet(iface: &NetworkInterface) -> Result<Ipv4Network> {
    iface
        .ips
        .iter()
        .find_map(|ip| match ip {
            ipnetwork::IpNetwork::V4(v4) => Some(*v4),
            _ => None,
        })
        .ok_or_else(|| anyhow!("No IPv4 address found on interface"))
}

/// Send ARP requests for every host in every subnet (deduplicated) and listen
/// for replies for `timeout`.
pub fn run_arp_scan(
    iface: &NetworkInterface,
    subnets: &[Ipv4Network],
    timeout: Duration,
) -> Result<Vec<ArpResult>> {
    let src_mac = iface
        .mac
        .ok_or_else(|| anyhow!("Interface has no MAC address"))?;

    let src_ip = iface
        .ips
        .iter()
        .find_map(|ip| match ip {
            ipnetwork::IpNetwork::V4(v4) => Some(v4.ip()),
            _ => None,
        })
        .ok_or_else(|| anyhow!("No IPv4 address on interface"))?;

    // Dedup targets across overlapping subnets (e.g. /16 iface IP + /24 list).
    let mut targets: Vec<Ipv4Addr> = HashSet::<Ipv4Addr>::from_iter(
        subnets
            .iter()
            .flat_map(|net| net.iter())
            .filter(|ip| *ip != src_ip),
    )
    .into_iter()
    .collect();
    targets.sort_unstable();

    if targets.is_empty() {
        return Err(anyhow!("No target addresses to scan"));
    }

    let (mut tx, mut rx) = match datalink::channel(iface, Default::default()) {
        Ok(Channel::Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => return Err(anyhow!("Unsupported channel type")),
        Err(e) => return Err(anyhow!("Failed to create channel: {}", e)),
    };

    info!(
        "Sending ARP requests for {} IPs across {} subnet(s){}...",
        targets.len(),
        subnets.len(),
        subnets
            .iter()
            .map(|s| format!(" {}", s))
            .take(4)
            .collect::<String>()
    );

    for target_ip in &targets {
        let mut buffer = [0u8; 42];
        build_arp_request(&mut buffer, src_mac, src_ip, *target_ip);
        if let Some(Err(e)) = tx.send_to(&buffer, None) {
            warn!("Failed to send ARP to {}: {}", target_ip, e);
        }
    }

    info!(
        "Listening for ARP replies ({}s timeout)...",
        timeout.as_secs()
    );

    let mut seen: HashSet<Ipv4Addr> = HashSet::new();
    let mut results = Vec::new();
    let start = std::time::Instant::now();

    while start.elapsed() < timeout {
        match rx.next() {
            Ok(data) => {
                if let Some(eth) = EthernetPacket::new(data)
                    && eth.get_ethertype() == EtherTypes::Arp
                    && let Some(arp) = ArpPacket::new(eth.payload())
                    && arp.get_operation() == ArpOperations::Reply
                {
                    let ip = arp.get_sender_proto_addr();
                    let mac = arp.get_sender_hw_addr();
                    if seen.insert(ip) {
                        info!("  Found: {} -> {}", ip, mac);
                        results.push(ArpResult {
                            ip: ip.to_string(),
                            mac: mac.to_string(),
                        });
                    }
                }
            }
            Err(_) => continue,
        }
    }

    // Always include ourselves: no ARP request is sent for src_ip, so the
    // scan would otherwise never list the host running it.
    if seen.insert(src_ip) {
        info!("  Found (self): {} -> {}", src_ip, src_mac);
        results.push(ArpResult {
            ip: src_ip.to_string(),
            mac: src_mac.to_string(),
        });
    }

    info!("Scan complete: {} devices found", results.len());
    Ok(results)
}

fn build_arp_request(
    buffer: &mut [u8; 42],
    src_mac: MacAddr,
    src_ip: Ipv4Addr,
    target_ip: Ipv4Addr,
) {
    // Ethernet header (14 bytes)
    {
        let mut eth = MutableEthernetPacket::new(&mut buffer[..]).unwrap();
        eth.set_destination(MacAddr::broadcast());
        eth.set_source(src_mac);
        eth.set_ethertype(EtherTypes::Arp);
    }
    // ARP payload (28 bytes at offset 14)
    {
        let mut arp = MutableArpPacket::new(&mut buffer[14..]).unwrap();
        arp.set_hardware_type(ArpHardwareTypes::Ethernet);
        arp.set_protocol_type(EtherTypes::Ipv4);
        arp.set_hw_addr_len(6);
        arp.set_proto_addr_len(4);
        arp.set_operation(ArpOperations::Request);
        arp.set_sender_hw_addr(src_mac);
        arp.set_sender_proto_addr(src_ip);
        arp.set_target_hw_addr(MacAddr::zero());
        arp.set_target_proto_addr(target_ip);
    }
}
