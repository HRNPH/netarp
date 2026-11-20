use std::collections::HashMap;
use std::net::ToSocketAddrs;

use crate::config::NamesCfg;

/// Compose the query name for a file entry: bare names get the suffix,
/// names that already contain dots are used as-is.
pub fn compose_fqdn(name: &str, suffix: &str) -> String {
    if name.contains('.') {
        name.to_string()
    } else {
        format!("{name}.{suffix}")
    }
}

/// Read the names file and resolve every entry to its IPv4 addresses via the
/// system resolver. Returns ip -> short name. Unresolvable entries are skipped
/// with a warning. The file is re-read on every call so it can be regenerated
/// externally without restarting netarp.
pub fn build_alias_map(cfg: &NamesCfg) -> HashMap<String, String> {
    let mut map = HashMap::new();
    let text = match std::fs::read_to_string(&cfg.file) {
        Ok(t) => t,
        Err(e) => {
            log::warn!(
                "names file {} unreadable: {} — skipping aliases",
                cfg.file,
                e
            );
            return map;
        }
    };

    for raw in text.lines() {
        let name = raw.trim();
        if name.is_empty() || name.starts_with('#') {
            continue;
        }
        let fqdn = compose_fqdn(name, &cfg.suffix);
        let host_port = format!("{fqdn}:0");
        match host_port.to_socket_addrs() {
            Ok(addrs) => {
                let mut resolved = 0;
                for addr in addrs {
                    if let std::net::SocketAddr::V4(v4) = addr {
                        let ip = v4.ip().to_string();
                        map.entry(ip).or_insert_with(|| name.to_string());
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

    log::info!("Alias map: {} entries from {}", map.len(), cfg.file);
    map
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
}
