use chrono::{DateTime, Utc};
use log::{error, info};

use crate::config::InfluxCfg;

/// Escapes a line-protocol tag value: commas, spaces and equals signs.
pub fn escape_tag(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for c in value.chars() {
        match c {
            ',' | ' ' | '=' => {
                out.push('\\');
                out.push(c);
            }
            _ => out.push(c),
        }
    }
    out
}

pub struct InfluxExporter {
    client: reqwest::Client,
    cfg: InfluxCfg,
    write_url: String,
    /// (network, label) sorted by prefix length desc for longest-prefix match.
    zones: Vec<(ipnetwork::Ipv4Network, String)>,
}

/// Device data forwarded to Influx; netarp-agnostic so callers can pass
/// anything that has the fields (the SeaORM device model satisfies this).
pub struct ExportDevice<'a> {
    pub ip: &'a str,
    pub mac: &'a str,
    pub alias: Option<&'a str>,
    pub vendor: Option<&'a str>,
    pub first_seen: DateTime<Utc>,
}

/// Mask an IPv4 dotted quad to a prefix length (must be byte-aligned),
/// returning e.g. "192.168.2.0/24".
pub fn subnet_of(ip: &str, prefix_bits: u8) -> Option<String> {
    if !prefix_bits.is_multiple_of(8) || prefix_bits > 32 {
        return None;
    }
    let octets: Vec<&str> = ip.split('.').collect();
    if octets.len() != 4 || octets.iter().any(|o| o.parse::<u8>().is_err()) {
        return None;
    }
    let keep = (prefix_bits / 8) as usize;
    let mut out: Vec<&str> = octets[..keep].to_vec();
    while out.len() < 4 {
        out.push("0");
    }
    Some(format!("{}/{prefix_bits}", out.join(".")))
}

impl InfluxExporter {
    pub fn new(cfg: InfluxCfg, zones: &Option<std::collections::BTreeMap<String, String>>) -> Self {
        let write_url = format!(
            "{}/api/v2/write?org={}&bucket={}&precision=ns",
            cfg.url.trim_end_matches('/'),
            cfg.org,
            cfg.bucket
        );
        let mut zones: Vec<(ipnetwork::Ipv4Network, String)> = zones
            .iter()
            .flatten()
            .filter_map(
                |(cidr, label)| match cidr.parse::<ipnetwork::Ipv4Network>() {
                    Ok(net) => Some((net, label.clone())),
                    Err(e) => {
                        log::warn!("invalid zone CIDR {cidr}: {e} — skipped");
                        None
                    }
                },
            )
            .collect();
        // Longest prefix first so the most specific zone wins.
        zones.sort_by_key(|(net, _)| std::cmp::Reverse(net.prefix()));
        Self {
            client: reqwest::Client::new(),
            cfg,
            write_url,
            zones,
        }
    }

    /// Longest-prefix zone label for an IP, if configured.
    fn zone_of(&self, ip: &str) -> Option<&str> {
        let ip: std::net::Ipv4Addr = ip.parse().ok()?;
        self.zones
            .iter()
            .find(|(net, _)| net.contains(ip))
            .map(|(_, label)| label.as_str())
    }

    /// Format the line-protocol body for one scan's devices.
    pub fn build_body(&self, devices: &[ExportDevice<'_>], scan_time: DateTime<Utc>) -> String {
        let ts = scan_time.timestamp_nanos_opt().unwrap_or_default();
        let mut lines = Vec::with_capacity(devices.len());
        for d in devices {
            let first_seen_ns = d.first_seen.timestamp_nanos_opt().unwrap_or_default();
            // Tags are always emitted (with "unknown" fallbacks) so the series
            // schema stays stable for downstream pivots.
            let subnet =
                subnet_of(d.ip, self.cfg.subnet_prefix).unwrap_or_else(|| "unknown".into());
            let zone = self.zone_of(d.ip).unwrap_or("unzoned");
            let tags = format!(
                "ip={},mac={},hostname={},vendor={},subnet={},zone={}",
                escape_tag(d.ip),
                escape_tag(d.mac),
                escape_tag(d.alias.unwrap_or("unknown")),
                escape_tag(d.vendor.unwrap_or("unknown")),
                escape_tag(&subnet),
                escape_tag(zone),
            );
            lines.push(format!(
                "{},{} alive=1i,first_seen_ns={}i {}",
                self.cfg.measurement, tags, first_seen_ns, ts
            ));
        }
        lines.join("\n")
    }

    /// Write one scan's devices. Log-and-continue on failure: export must
    /// never take the scanner down.
    pub async fn write(&self, devices: &[ExportDevice<'_>], scan_time: DateTime<Utc>) {
        if devices.is_empty() {
            return;
        }
        let token = match &self.cfg.token {
            Some(t) if !t.is_empty() => t.clone(),
            _ => {
                error!(
                    "influx export enabled but no token set (influx.token / NETARP_INFLUX_TOKEN)"
                );
                return;
            }
        };
        let body = self.build_body(devices, scan_time);
        let resp = self
            .client
            .post(&self.write_url)
            .header("Authorization", format!("Token {token}"))
            .header("Content-Type", "text/plain")
            .body(body)
            .send()
            .await;
        match resp {
            Ok(r) if r.status().is_success() => {
                info!(
                    "Influx: wrote {} points to {}",
                    devices.len(),
                    self.cfg.bucket
                );
            }
            Ok(r) => {
                error!(
                    "Influx write failed: {} {}",
                    r.status(),
                    r.text().await.unwrap_or_default()
                );
            }
            Err(e) => error!("Influx write failed: {e}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    fn cfg() -> InfluxCfg {
        InfluxCfg {
            url: "http://localhost:8086".into(),
            org: "magika".into(),
            bucket: "network".into(),
            measurement: "lan".into(),
            token: Some("t".into()),
            subnet_prefix: 24,
        }
    }

    fn zones() -> Option<std::collections::BTreeMap<String, String>> {
        Some(
            [
                ("192.168.1.0/24".to_string(), "homelab-infra".to_string()),
                ("192.168.2.0/24".to_string(), "home-dhcp".to_string()),
                ("192.168.0.0/16".to_string(), "lan".to_string()),
            ]
            .into_iter()
            .collect(),
        )
    }

    #[test]
    fn tag_escaping() {
        assert_eq!(escape_tag("a b"), "a\\ b");
        assert_eq!(escape_tag("x,y=z"), "x\\,y\\=z");
        assert_eq!(escape_tag("clean"), "clean");
    }

    #[test]
    fn subnet_masking() {
        assert_eq!(
            subnet_of("192.168.2.41", 24).as_deref(),
            Some("192.168.2.0/24")
        );
        assert_eq!(subnet_of("10.1.99.5", 16).as_deref(), Some("10.1.0.0/16"));
        assert_eq!(subnet_of("192.168.2.41", 0).as_deref(), Some("0.0.0.0/0"));
        assert_eq!(subnet_of("not-an-ip", 24), None);
        assert_eq!(subnet_of("192.168.2.41", 22), None); // non-byte-aligned
    }

    #[test]
    fn zone_longest_prefix_wins() {
        let ex = InfluxExporter::new(cfg(), &zones());
        assert_eq!(ex.zone_of("192.168.1.10"), Some("homelab-infra"));
        assert_eq!(ex.zone_of("192.168.2.41"), Some("home-dhcp"));
        assert_eq!(ex.zone_of("192.168.9.1"), Some("lan")); // falls to /16
        assert_eq!(ex.zone_of("10.0.0.1"), None);
    }

    #[test]
    fn body_format() {
        let ex = InfluxExporter::new(cfg(), &zones());
        let t = Utc.timestamp_opt(1700000000, 0).unwrap();
        let dev = ExportDevice {
            ip: "192.168.1.101",
            mac: "de:a6:32:ff:fe:76",
            alias: Some("rakazo"),
            vendor: None,
            first_seen: t,
        };
        let body = ex.build_body(&[dev], t);
        assert_eq!(
            body,
            "lan,ip=192.168.1.101,mac=de:a6:32:ff:fe:76,hostname=rakazo,vendor=unknown,subnet=192.168.1.0/24,zone=homelab-infra alive=1i,first_seen_ns=1700000000000000000i 1700000000000000000"
        );
    }

    #[test]
    fn body_format_without_zones() {
        let ex = InfluxExporter::new(cfg(), &None);
        let t = Utc.timestamp_opt(1700000000, 0).unwrap();
        let dev = ExportDevice {
            ip: "192.168.2.41",
            mac: "de:a6:32:ff:fe:76",
            alias: None,
            vendor: None,
            first_seen: t,
        };
        let body = ex.build_body(&[dev], t);
        assert!(body.contains("subnet=192.168.2.0/24,zone=unzoned"));
    }
}
