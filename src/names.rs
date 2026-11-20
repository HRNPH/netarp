use std::collections::HashMap;
use std::net::ToSocketAddrs;

use crate::config::NamesCfg;

/// Alias maps built from the names file. Devices are matched by MAC first
/// (exact, stable), then by IP (DNS-resolved names).
#[derive(Debug, Default, Clone)]
pub struct AliasMaps {
    pub by_mac: HashMap<String, String>,
    pub by_ip: HashMap<String, String>,
}

impl AliasMaps {
    pub fn total(&self) -> usize {
        self.by_mac.len() + self.by_ip.len()
    }
}

/// A MAC is exactly 17 chars: 6 hex octets separated by ':' or '-'.
pub fn looks_like_mac(s: &str) -> bool {
    let b = s.as_bytes();
    b.len() == 17
        && b.iter().enumerate().all(|(i, c)| {
            if i % 3 == 2 {
                *c == b':' || *c == b'-'
            } else {
                c.is_ascii_hexdigit()
            }
        })
}

/// Compose the query name for a file entry: bare names get the suffix,
/// names that already contain dots are used as-is.
pub fn compose_fqdn(name: &str, suffix: &str) -> String {
    if name.contains('.') {
        name.to_string()
    } else {
        format!("{name}.{suffix}")
    }
}

/// Read the names file and build alias maps. Supported line formats:
///
///   01:23:45:67:89:ab devicename     -> MAC match (preferred)
///   hostname                         -> resolved via DNS to IPs, IP match
///
/// The file is re-read on every call so it can be regenerated externally
/// without restarting netarp.
pub fn build_alias_maps(cfg: &NamesCfg) -> AliasMaps {
    let mut maps = AliasMaps::default();
    let text = match std::fs::read_to_string(&cfg.file) {
        Ok(t) => t,
        Err(e) => {
            log::warn!(
                "names file {} unreadable: {} — skipping aliases",
                cfg.file,
                e
            );
            return maps;
        }
    };

    for raw in text.lines() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        // "MAC name" line: direct MAC match.
        if let Some((mac, name)) = line.split_once(char::is_whitespace) {
            let mac = mac.trim();
            let name = name.trim();
            if looks_like_mac(mac) && !name.is_empty() {
                maps.by_mac
                    .entry(mac.to_ascii_lowercase())
                    .or_insert_with(|| name.to_string());
                continue;
            }
        }

        // Bare hostname line: resolve to IPs via the system resolver.
        let name = line;
        let fqdn = compose_fqdn(name, &cfg.suffix);
        let host_port = format!("{fqdn}:0");
        match host_port.to_socket_addrs() {
            Ok(addrs) => {
                let mut resolved = 0;
                for addr in addrs {
                    if let std::net::SocketAddr::V4(v4) = addr {
                        let ip = v4.ip().to_string();
                        maps.by_ip.entry(ip).or_insert_with(|| name.to_string());
                        resolved += 1;
                    }
                }
                if resolved == 0 {
                    log::debug!("no A record for {fqdn}");
                }
            }
            Err(e) => log::debug!("resolve {fqdn} failed: {e}"),
        }
    }

    maps
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bare_name_gets_suffix() {
        assert_eq!(compose_fqdn("rakazo", "magika"), "rakazo.magika");
    }

    #[test]
    fn fqdn_kept_as_is() {
        assert_eq!(compose_fqdn("box.lan", "magika"), "box.lan");
    }

    #[test]
    fn mac_detection() {
        assert!(looks_like_mac("de:a6:32:ff:fe:76"));
        assert!(looks_like_mac("DE-A6-32-FF-FE-76"));
        assert!(!looks_like_mac("192.168.1.1"));
        assert!(!looks_like_mac("de:a6:32:ff:fe")); // too short
        assert!(!looks_like_mac("hostname"));
    }

    #[test]
    fn mac_lines_build_by_mac_map() {
        let dir = std::env::temp_dir().join("netarp-names-test");
        std::fs::create_dir_all(&dir).unwrap();
        let f = dir.join("names.txt");
        // DNS-dependent hostname lines are environment-specific; only assert
        // they don't panic and that MAC lines map correctly.
        std::fs::write(
            &f,
            "# comment\n\nBC:24:11:06:F6:60 rakazo\nnonexistent-host-xyz\n",
        )
        .unwrap();
        let cfg = NamesCfg {
            file: f.to_string_lossy().to_string(),
            suffix: "magika".into(),
        };
        let maps = build_alias_maps(&cfg);
        assert_eq!(
            maps.by_mac.get("bc:24:11:06:f6:60").map(String::as_str),
            Some("rakazo")
        );
    }
}
