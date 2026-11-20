use anyhow::{Context, Result};
use clap::Parser;
use figment::{
    Figment,
    providers::{Format, Serialized, Toml},
};
use serde::{Deserialize, Serialize};

/// Layered configuration: defaults < TOML file < environment < CLI flags.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct Config {
    pub scanner: ScannerCfg,
    pub database: DatabaseCfg,
    #[cfg(feature = "graphql")]
    pub api: ApiCfg,
    #[cfg(feature = "influx")]
    pub influx: Option<InfluxCfg>,
    pub names: Option<NamesCfg>,
    /// Subnet -> label map. A device's IP is matched against these CIDRs
    /// (longest prefix wins) and exported with the label as the `zone` tag.
    /// Example:
    ///
    /// ```toml
    /// [zones]
    /// "192.168.1.0/24" = "homelab-infra"
    /// "192.168.2.0/24" = "home-dhcp"
    /// ```
    pub zones: Option<std::collections::BTreeMap<String, String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct ScannerCfg {
    /// Network interface name; autodetected when absent.
    pub interface: Option<String>,
    /// Subnets to scan (CIDR); autodetected when absent.
    pub subnets: Option<Vec<String>>,
    /// Seconds between scans.
    pub interval_secs: u64,
    /// Seconds to listen for ARP replies per scan.
    pub timeout_secs: u64,
    /// Run a single scan and exit.
    pub once: bool,
}

impl Default for ScannerCfg {
    fn default() -> Self {
        Self {
            interface: None,
            subnets: None,
            interval_secs: 300,
            timeout_secs: 5,
            once: false,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct DatabaseCfg {
    /// SeaORM URL, e.g. sqlite:///var/lib/netarp/netarp.db?mode=rwc
    pub url: String,
}

impl Default for DatabaseCfg {
    fn default() -> Self {
        Self {
            url: "sqlite://netarp.db?mode=rwc".to_string(),
        }
    }
}

#[cfg(feature = "graphql")]
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct ApiCfg {
    /// Bind address for the GraphQL API, e.g. 0.0.0.0:4000
    pub bind: String,
}

#[cfg(feature = "graphql")]
impl Default for ApiCfg {
    fn default() -> Self {
        Self {
            bind: "0.0.0.0:4000".to_string(),
        }
    }
}

#[cfg(feature = "influx")]
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct InfluxCfg {
    pub url: String,
    pub org: String,
    pub bucket: String,
    #[serde(default = "default_measurement")]
    pub measurement: String,
    /// Prefer the NETARP_INFLUX_TOKEN environment variable.
    pub token: Option<String>,
    /// Emit a `subnet` tag per device, derived from its IP by masking to this
    /// prefix length (e.g. 24 -> "192.168.1.0/24"). 0 disables the tag.
    #[serde(default = "default_subnet_prefix")]
    pub subnet_prefix: u8,
}

fn default_subnet_prefix() -> u8 {
    24
}

#[cfg(feature = "influx")]
fn default_measurement() -> String {
    "lan".to_string()
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct NamesCfg {
    /// File with one hostname per line, re-read before every scan.
    pub file: String,
    /// Domain suffix appended to bare hostnames.
    #[serde(default = "default_suffix")]
    pub suffix: String,
}

fn default_suffix() -> String {
    "local".to_string()
}

/// CLI overrides (highest precedence). Kept close to the v0.1 flags.
#[derive(Debug, Clone, Parser)]
#[command(
    name = "netarp",
    about = "Network observer using ARP discovery",
    version
)]
pub struct Args {
    /// Path to a TOML config file (also searched at ./netarp.toml and /etc/netarp/config.toml)
    #[arg(long, global = true)]
    pub config: Option<String>,

    /// Network interface (autodetected if omitted)
    #[arg(short, long)]
    pub interface: Option<String>,

    /// Subnet to scan, CIDR; repeat for multiple subnets
    #[arg(short = 's', long = "subnet")]
    pub subnets: Option<Vec<String>>,

    /// Scan interval in seconds
    #[arg(short = 'I', long)]
    pub interval: Option<u64>,

    /// Seconds to listen for ARP replies
    #[arg(long)]
    pub timeout: Option<u64>,

    /// Run one scan and exit
    #[arg(long)]
    pub once: bool,

    /// SQLite URL (overrides database.url)
    #[arg(long)]
    pub db_url: Option<String>,

    /// GraphQL API bind address (overrides api.bind)
    #[cfg(feature = "graphql")]
    #[arg(short = 'p', long)]
    pub port: Option<u16>,
}

/// Where a config file may live, in order.
const CONFIG_SEARCH: &[&str] = &["netarp.toml", "/etc/netarp/config.toml"];

pub fn load(args: &Args) -> Result<Config> {
    let mut fig = Figment::from(Serialized::defaults(Config::default()));

    // Config file: explicit path, else first existing search location.
    let file = match &args.config {
        Some(p) => Some(p.clone()),
        None => CONFIG_SEARCH
            .iter()
            .find(|p| std::path::Path::new(p).exists())
            .map(|p| p.to_string()),
    };
    if let Some(path) = file {
        log::info!("Loading config file: {path}");
        fig = fig.merge(Toml::file_exact(path));
    }

    // Environment overrides: explicit NETARP_* keys applied on top of the file.
    let env = |key: &str| std::env::var(format!("NETARP_{key}")).ok();
    let mut over = serde_json::Map::new();
    let mut scanner = serde_json::Map::new();
    if let Some(v) = env("INTERFACE") {
        scanner.insert("interface".into(), v.into());
    }
    if let Some(Ok(n)) = env("INTERVAL_SECS")
        .or_else(|| env("INTERVAL"))
        .map(|v| v.parse::<u64>())
    {
        scanner.insert("interval_secs".into(), n.into());
    }
    if let Some(Ok(n)) = env("TIMEOUT_SECS")
        .or_else(|| env("TIMEOUT"))
        .map(|v| v.parse::<u64>())
    {
        scanner.insert("timeout_secs".into(), n.into());
    }
    if let Some(Ok(b)) = env("ONCE").map(|v| v.parse::<bool>()) {
        scanner.insert("once".into(), b.into());
    }
    if !scanner.is_empty() {
        over.insert("scanner".into(), scanner.into());
    }
    if let Some(v) = env("DB_URL") {
        over.insert("database".into(), serde_json::json!({ "url": v }));
    }
    #[cfg(feature = "graphql")]
    if let Some(v) = env("API_BIND") {
        over.insert("api".into(), serde_json::json!({ "bind": v }));
    }
    let mut influx_over = serde_json::Map::new();
    if let Some(v) = env("INFLUX_URL") {
        influx_over.insert("url".into(), v.into());
    }
    if let Some(v) = env("INFLUX_ORG") {
        influx_over.insert("org".into(), v.into());
    }
    if let Some(v) = env("INFLUX_BUCKET") {
        influx_over.insert("bucket".into(), v.into());
    }
    if let Some(v) = env("INFLUX_TOKEN") {
        influx_over.insert("token".into(), v.into());
    }
    if !influx_over.is_empty() {
        over.insert("influx".into(), influx_over.into());
    }
    if env("NAMES_FILE").is_some() || env("NAMES_SUFFIX").is_some() {
        let mut names = serde_json::Map::new();
        if let Some(v) = env("NAMES_FILE") {
            names.insert("file".into(), v.into());
        }
        if let Some(v) = env("NAMES_SUFFIX") {
            names.insert("suffix".into(), v.into());
        }
        over.insert("names".into(), names.into());
    }
    if !over.is_empty() {
        fig = fig.merge(Serialized::defaults(serde_json::Value::Object(over)));
    }

    // CLI overrides last.
    let mut cli = serde_json::Map::new();
    let mut scanner = serde_json::Map::new();
    if let Some(i) = &args.interface {
        scanner.insert("interface".into(), i.clone().into());
    }
    if let Some(s) = &args.subnets {
        scanner.insert("subnets".into(), s.clone().into());
    }
    if let Some(i) = args.interval {
        scanner.insert("interval_secs".into(), i.into());
    }
    if let Some(t) = args.timeout {
        scanner.insert("timeout_secs".into(), t.into());
    }
    if args.once {
        scanner.insert("once".into(), true.into());
    }
    if !scanner.is_empty() {
        cli.insert("scanner".into(), scanner.into());
    }
    if let Some(u) = &args.db_url {
        cli.insert("database".into(), serde_json::json!({ "url": u }));
    }
    #[cfg(feature = "graphql")]
    if let Some(p) = args.port {
        cli.insert(
            "api".into(),
            serde_json::json!({ "bind": format!("0.0.0.0:{p}") }),
        );
    }
    if !cli.is_empty() {
        fig = fig.merge(Serialized::defaults(serde_json::Value::Object(cli)));
    }

    fig.extract()
        .with_context(|| "invalid configuration (check file, env, and flags)")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base_args() -> Args {
        Args {
            config: None,
            interface: None,
            subnets: None,
            interval: None,
            timeout: None,
            once: false,
            db_url: None,
            #[cfg(feature = "graphql")]
            port: None,
        }
    }

    #[test]
    fn defaults_when_no_layers() {
        let cfg = load(&base_args()).unwrap();
        assert_eq!(cfg.scanner.interval_secs, 300);
        assert_eq!(cfg.database.url, "sqlite://netarp.db?mode=rwc");
        assert!(cfg.names.is_none());
    }

    #[test]
    fn cli_overrides_defaults() {
        let mut args = base_args();
        args.interval = Some(120);
        args.once = true;
        let cfg = load(&args).unwrap();
        assert_eq!(cfg.scanner.interval_secs, 120);
        assert!(cfg.scanner.once);
    }

    #[test]
    fn figment_layer_order_file_then_cli() {
        // Defaults < file < CLI: simulate by merging providers directly.
        let fig = Figment::from(Serialized::defaults(Config::default()))
            .merge(Serialized::defaults(
                serde_json::json!({ "scanner": { "interval_secs": 60 } }),
            ))
            .merge(Serialized::defaults(
                serde_json::json!({ "scanner": { "interval_secs": 15 } }),
            ));
        let cfg: Config = fig.extract().unwrap();
        assert_eq!(cfg.scanner.interval_secs, 15);
    }
}
