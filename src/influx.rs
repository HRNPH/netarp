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

impl InfluxExporter {
    pub fn new(cfg: InfluxCfg) -> Self {
        let write_url = format!(
            "{}/api/v2/write?org={}&bucket={}&precision=ns",
            cfg.url.trim_end_matches('/'),
            cfg.org,
            cfg.bucket
        );
        Self {
            client: reqwest::Client::new(),
            cfg,
            write_url,
        }
    }

    /// Format the line-protocol body for one scan's devices.
    pub fn build_body(&self, devices: &[ExportDevice<'_>], scan_time: DateTime<Utc>) -> String {
        let ts = scan_time.timestamp_nanos_opt().unwrap_or_default();
        let mut lines = Vec::with_capacity(devices.len());
        for d in devices {
            let first_seen_ns = d.first_seen.timestamp_nanos_opt().unwrap_or_default();
            // Tags are always emitted (with "unknown" fallbacks) so the series
            // schema stays stable for downstream pivots.
            let tags = format!(
                "ip={},mac={},hostname={},vendor={}",
                escape_tag(d.ip),
                escape_tag(d.mac),
                escape_tag(d.alias.unwrap_or("unknown")),
                escape_tag(d.vendor.unwrap_or("unknown")),
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
        }
    }

    #[test]
    fn tag_escaping() {
        assert_eq!(escape_tag("a b"), "a\\ b");
        assert_eq!(escape_tag("x,y=z"), "x\\,y\\=z");
        assert_eq!(escape_tag("clean"), "clean");
    }

    #[test]
    fn body_format() {
        let ex = InfluxExporter::new(cfg());
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
            "lan,ip=192.168.1.101,mac=de:a6:32:ff:fe:76,hostname=rakazo,vendor=unknown alive=1i,first_seen_ns=1700000000000000000i 1700000000000000000"
        );
    }
}
