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
    tokio::spawn(async move {
        loop {
            info!("Starting ARP scan...");
            let iface = scan_iface.clone();
            let net = subnet;
            let results =
                match tokio::task::spawn_blocking(move || scanner::run_arp_scan(&iface, net)).await
                {
                    Ok(Ok(r)) => r,
                    Ok(Err(e)) => {
                        log::error!("Scan failed: {}", e);
                        vec![]
                    }
                    Err(e) => {
                        log::error!("Task panicked: {}", e);
                        vec![]
                    }
                };

            if !results.is_empty() {
                info!("Upserting {} devices...", results.len());
                if let Err(e) = db::upsert_scan_results(&scan_db, results).await {
                    log::error!("DB update failed: {}", e);
                }
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
