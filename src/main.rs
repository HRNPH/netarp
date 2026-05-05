mod db;
mod graphql;
mod models;
mod scanner;

use std::time::Duration;

use anyhow::Result;
use clap::Parser;
use log::info;

#[derive(Parser)]
#[command(name = "netarp", about = "Network observer using ARP discovery")]
struct Args {
    /// Network interface (auto-detected if omitted)
    #[arg(short, long)]
    interface: Option<String>,

    /// Subnet to scan, CIDR notation (auto-detected if omitted)
    #[arg(short, long)]
    subnet: Option<String>,

    /// Scan interval in seconds
    #[arg(short, long, default_value = "300")]
    interval: u64,

    /// API server port
    #[arg(short, long, default_value = "4000")]
    port: u16,

    /// Database path
    #[arg(long, default_value = "netarp.db")]
    db_path: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::init();
    let args = Args::parse();

    let db = db::init_db(&args.db_path).await?;
    info!("Database ready");

    // Resolve interface
    let iface = match &args.interface {
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

    // Resolve subnet
    let subnet = match &args.subnet {
        Some(s) => s.parse()?,
        None => {
            let net = scanner::get_interface_subnet(&iface)?;
            info!("Scanning subnet: {}", net);
            net
        }
    };

    // Background scanner
    let scan_db = db.clone();
    let scan_iface = iface.clone();
    let scan_interval = Duration::from_secs(args.interval);
    let subnet_str = subnet.to_string();
    tokio::spawn(async move {
        loop {
            info!("Starting ARP scan...");

            let scan_id = match db::create_scan(&scan_db, &subnet_str, &scan_iface.name).await {
                Ok(id) => id,
                Err(e) => {
                    log::error!("Failed to create scan record: {}", e);
                    tokio::time::sleep(scan_interval).await;
                    continue;
                }
            };

            let iface = scan_iface.clone();
            let net = subnet;
            let results =
                match tokio::task::spawn_blocking(move || scanner::run_arp_scan(&iface, net)).await
                {
                    Ok(Ok(r)) => r,
                    Ok(Err(e)) => {
                        log::error!("Scan failed: {}", e);
                        let _ = db::fail_scan(&scan_db, &scan_id).await;
                        tokio::time::sleep(scan_interval).await;
                        continue;
                    }
                    Err(e) => {
                        log::error!("Task panicked: {}", e);
                        let _ = db::fail_scan(&scan_db, &scan_id).await;
                        tokio::time::sleep(scan_interval).await;
                        continue;
                    }
                };

            if !results.is_empty() {
                info!("Upserting {} devices...", results.len());
                match db::upsert_scan_results(&scan_db, results).await {
                    Ok(summary) => {
                        let device_count = summary.results.len() as i32;
                        if let Err(e) =
                            db::store_scan_results(&scan_db, &scan_id, &summary.results).await
                        {
                            log::error!("Failed to store scan results: {}", e);
                        }
                        if let Err(e) =
                            db::complete_scan(&scan_db, &scan_id, device_count, &summary).await
                        {
                            log::error!("Failed to complete scan: {}", e);
                        }
                    }
                    Err(e) => {
                        log::error!("DB update failed: {}", e);
                        let _ = db::fail_scan(&scan_db, &scan_id).await;
                    }
                }
            } else {
                let empty = models::UpsertSummary {
                    new_count: 0,
                    updated_count: 0,
                    failed_count: 0,
                    results: vec![],
                };
                let _ = db::complete_scan(&scan_db, &scan_id, 0, &empty).await;
            }

            tokio::time::sleep(scan_interval).await;
        }
    });

    // GraphQL API
    let schema = graphql::create_schema(db);
    let app = axum::Router::new()
        .route("/graphql", axum::routing::post(graphql::graphql_handler))
        .route("/graphql", axum::routing::get(graphql::graphql_playground))
        .layer(axum::Extension(schema));

    let addr = format!("0.0.0.0:{}", args.port);
    let listener = tokio::net::TcpListener::bind(&addr).await?;
    info!("NetArp server started");
    info!("  GraphQL API:  http://{}", listener.local_addr()?);
    info!("  Playground:   http://{}/graphql", listener.local_addr()?);
    info!("  Interface:    {}", iface.name);
    info!("  Subnet:       {}", subnet);
    info!("  Scan interval: {}s", args.interval);
    axum::serve(listener, app).await?;

    Ok(())
}
