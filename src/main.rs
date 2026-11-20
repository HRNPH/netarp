mod config;
mod db;
mod entity;
mod models;
mod names;
mod scanner;

#[cfg(feature = "graphql")]
mod graphql;

#[cfg(feature = "influx")]
mod influx;

use std::time::Duration;

use anyhow::Result;
use clap::Parser;
use config::{Args, NamesCfg};
use log::info;
use sea_orm::DatabaseConnection;

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::init();
    let args = Args::parse();
    let cfg = config::load(&args)?;

    let db = db::connect_and_migrate(&cfg.database.url).await?;

    // Resolve interface
    let iface = match &cfg.scanner.interface {
        Some(name) => pnet::datalink::interfaces()
            .into_iter()
            .find(|i| i.name == *name)
            .ok_or_else(|| anyhow::anyhow!("Interface '{}' not found", name))?,
        None => {
            let iface = scanner::find_default_interface()?;
            info!("Using interface: {}", iface.name);
            iface
        }
    };

    // Resolve subnets
    let subnets: Vec<ipnetwork::Ipv4Network> = match &cfg.scanner.subnets {
        Some(list) => {
            let mut nets = Vec::with_capacity(list.len());
            for s in list {
                nets.push(s.parse()?);
            }
            info!("Scanning subnets: {:?}", nets);
            nets
        }
        None => {
            let net = scanner::get_interface_subnet(&iface)?;
            info!("Scanning subnet: {}", net);
            vec![net]
        }
    };

    #[cfg(feature = "influx")]
    let exporter = cfg
        .influx
        .as_ref()
        .map(|icfg| influx::InfluxExporter::new(icfg.clone(), &cfg.zones));

    // Everything the scan loop needs, owned by the task.
    let loop_db = db.clone();
    let loop_iface = iface.clone();
    let interval = Duration::from_secs(cfg.scanner.interval_secs);
    let timeout = Duration::from_secs(cfg.scanner.timeout_secs);
    let once = cfg.scanner.once;
    let loop_subnets = subnets.clone();
    let loop_names = cfg.names.clone();
    let subnets_str = subnets
        .iter()
        .map(|n| n.to_string())
        .collect::<Vec<_>>()
        .join(", ");
    let task_subnets_str = subnets_str.clone();

    let _scanner_task = tokio::spawn(async move {
        let mut iteration: u64 = 0;
        loop {
            iteration += 1;
            info!("Starting ARP scan #{iteration}...");
            run_one_scan(
                &loop_db,
                &loop_iface,
                &loop_subnets,
                &task_subnets_str,
                timeout,
                &loop_names,
                #[cfg(feature = "influx")]
                exporter.as_ref(),
            )
            .await;

            if once {
                info!("scanner.once is set — exiting after single scan");
                break;
            }
            tokio::time::sleep(interval).await;
        }
    });

    // GraphQL API (feature "graphql"); without it we just wait on the scanner.
    #[cfg(feature = "graphql")]
    {
        let schema = graphql::create_schema(db);
        let app = axum::Router::new()
            .route("/graphql", axum::routing::post(graphql::graphql_handler))
            .route("/graphql", axum::routing::get(graphql::graphql_playground))
            .layer(axum::Extension(schema));

        let listener = tokio::net::TcpListener::bind(&cfg.api.bind).await?;
        info!("NetArp server started");
        info!("  GraphQL API:  http://{}", listener.local_addr()?);
        info!("  Playground:   http://{}/graphql", listener.local_addr()?);
        info!("  Interface:    {}", iface.name);
        info!("  Subnets:      {}", subnets_str);
        info!("  Interval:     {:?}", interval);
        axum::serve(listener, app).await?;
    }

    #[cfg(not(feature = "graphql"))]
    _scanner_task.await?;

    Ok(())
}

#[cfg_attr(not(feature = "influx"), allow(unused_variables))]
async fn run_one_scan(
    db: &DatabaseConnection,
    iface: &pnet::datalink::NetworkInterface,
    subnets: &[ipnetwork::Ipv4Network],
    subnets_str: &str,
    timeout: Duration,
    names_cfg: &Option<NamesCfg>,
    #[cfg(feature = "influx")] exporter: Option<&influx::InfluxExporter>,
) {
    let scan_id = match db::repo::create_scan(db, subnets_str, &iface.name).await {
        Ok(id) => id,
        Err(e) => {
            log::error!("Failed to create scan record: {e}");
            return;
        }
    };

    let scan_iface = iface.clone();
    let scan_nets = subnets.to_vec();
    let results = match tokio::task::spawn_blocking(move || {
        scanner::run_arp_scan(&scan_iface, &scan_nets, timeout)
    })
    .await
    {
        Ok(Ok(r)) => r,
        Ok(Err(e)) => {
            log::error!("Scan failed: {e}");
            let _ = db::repo::fail_scan(db, scan_id).await;
            return;
        }
        Err(e) => {
            log::error!("Task panicked: {e}");
            let _ = db::repo::fail_scan(db, scan_id).await;
            return;
        }
    };

    // Alias maps are rebuilt every scan so the names file can change at runtime.
    let alias_maps = match names_cfg {
        Some(nc) => names::build_alias_maps(nc),
        None => names::AliasMaps::default(),
    };
    log::info!(
        "Alias maps: {} entries ({} MAC, {} IP)",
        alias_maps.total(),
        alias_maps.by_mac.len(),
        alias_maps.by_ip.len()
    );

    if results.is_empty() {
        let empty = models::UpsertSummary {
            new_count: 0,
            updated_count: 0,
            failed_count: 0,
            results: vec![],
        };
        let _ = db::repo::complete_scan(db, scan_id, 0, &empty).await;
        return;
    }

    info!("Upserting {} devices...", results.len());
    match db::repo::upsert_scan_results(db, results, &alias_maps).await {
        Ok((summary, devices)) => {
            let device_count = summary.results.len() as i32;
            if let Err(e) = db::repo::store_scan_results(db, scan_id, &summary.results).await {
                log::error!("Failed to store scan results: {e}");
            }
            if let Err(e) = db::repo::complete_scan(db, scan_id, device_count, &summary).await {
                log::error!("Failed to complete scan: {e}");
            }

            #[cfg(feature = "influx")]
            if let Some(ex) = exporter {
                let exports: Vec<influx::ExportDevice<'_>> = devices
                    .iter()
                    .map(|d| influx::ExportDevice {
                        ip: &d.ip,
                        mac: &d.mac,
                        alias: d.alias.as_deref(),
                        vendor: d.vendor.as_deref(),
                        first_seen: d.first_seen,
                    })
                    .collect();
                ex.write(&exports, chrono::Utc::now()).await;
            }
        }
        Err(e) => {
            log::error!("DB update failed: {e}");
            let _ = db::repo::fail_scan(db, scan_id).await;
        }
    }
}
