use anyhow::Result;
use chrono::Utc;
use log::info;
use serde::{Deserialize, Serialize};
use surrealdb::engine::local::RocksDb;
use surrealdb::sql::Datetime;
use surrealdb::Surreal;

use crate::models::{
    ArpResult, Device, HistoryEvent, IndividualResult, Scan, ScanResult, UpsertSummary,
};

pub type Db = Surreal<surrealdb::engine::local::Db>;

#[derive(Debug, Serialize, Deserialize)]
struct MigrationRecord {
    id: String,
    applied_at: String,
}

/// All migrations in order. Add new ones at the end.
const MIGRATIONS: &[(&str, &str)] = &[
    (
        "001_init_schema",
        "
        DEFINE TABLE device SCHEMAFULL;
        DEFINE FIELD IF NOT EXISTS ip ON device TYPE string;
        DEFINE FIELD IF NOT EXISTS mac ON device TYPE string;
        DEFINE FIELD IF NOT EXISTS alias ON device TYPE option<string>;
        DEFINE FIELD IF NOT EXISTS vendor ON device TYPE option<string>;
        DEFINE FIELD IF NOT EXISTS first_seen ON device TYPE datetime;
        DEFINE FIELD IF NOT EXISTS last_seen ON device TYPE datetime;

        DEFINE TABLE event SCHEMAFULL;
        DEFINE FIELD IF NOT EXISTS device_mac ON event TYPE string;
        DEFINE FIELD IF NOT EXISTS timestamp ON event TYPE datetime;
        DEFINE FIELD IF NOT EXISTS kind ON event TYPE string;
        DEFINE FIELD IF NOT EXISTS detail ON event TYPE option<string>;

        DEFINE INDEX IF NOT EXISTS idx_device_mac ON device COLUMNS mac;
        DEFINE INDEX IF NOT EXISTS idx_event_mac ON event COLUMNS device_mac;
        DEFINE INDEX IF NOT EXISTS idx_event_ts ON event COLUMNS timestamp;
        ",
    ),
    (
        "002_scan_tracking",
        "
        DEFINE TABLE scan SCHEMAFULL;
        DEFINE FIELD IF NOT EXISTS started_at ON scan TYPE datetime;
        DEFINE FIELD IF NOT EXISTS finished_at ON scan TYPE option<datetime>;
        DEFINE FIELD IF NOT EXISTS subnet ON scan TYPE string;
        DEFINE FIELD IF NOT EXISTS interface ON scan TYPE string;
        DEFINE FIELD IF NOT EXISTS status ON scan TYPE string;
        DEFINE FIELD IF NOT EXISTS device_count ON scan TYPE option<int>;
        DEFINE FIELD IF NOT EXISTS new_count ON scan TYPE option<int>;
        DEFINE FIELD IF NOT EXISTS updated_count ON scan TYPE option<int>;
        DEFINE FIELD IF NOT EXISTS failed_count ON scan TYPE option<int>;

        DEFINE TABLE scan_result SCHEMAFULL;
        DEFINE FIELD IF NOT EXISTS scan_id ON scan_result TYPE string;
        DEFINE FIELD IF NOT EXISTS ip ON scan_result TYPE string;
        DEFINE FIELD IF NOT EXISTS mac ON scan_result TYPE string;
        DEFINE FIELD IF NOT EXISTS status ON scan_result TYPE string;
        DEFINE FIELD IF NOT EXISTS error ON scan_result TYPE option<string>;

        DEFINE INDEX IF NOT EXISTS idx_scan_started ON scan COLUMNS started_at;
        DEFINE INDEX IF NOT EXISTS idx_scan_result_scan_id ON scan_result COLUMNS scan_id;
        ",
    ),
];

pub async fn init_db(path: &str) -> Result<Db> {
    let db = Surreal::new::<RocksDb>(path).await?;
    db.use_ns("netarp").use_db("network").await?;

    db.query("DEFINE TABLE IF NOT EXISTS _migration SCHEMAFULL;")
        .await?;
    db.query("DEFINE FIELD IF NOT EXISTS applied_at ON _migration TYPE string;")
        .await?;

    run_migrations(&db).await?;

    info!("Database initialized at {}", path);
    Ok(db)
}

async fn run_migrations(db: &Db) -> Result<()> {
    let applied: Vec<MigrationRecord> = db
        .query("SELECT id, applied_at FROM _migration")
        .await?
        .take(0)?;

    let applied_ids: Vec<String> = applied.into_iter().map(|m| m.id).collect();

    let mut ran = 0u32;
    for (id, sql) in MIGRATIONS {
        if applied_ids.iter().any(|a| a.ends_with(id)) {
            continue;
        }

        info!("Running migration: {}", id);
        if let Err(e) = db.query(*sql).await {
            log::error!("Migration {} FAILED: {}", id, e);
            anyhow::bail!("Migration {} failed: {}", id, e);
        }

        let now = Utc::now().to_rfc3339();
        db.query(
            "
            CREATE _migration SET
                applied_at = $now
            ",
        )
        .bind(("now", now))
        .await?;

        info!("Migration {} applied successfully", id);
        ran += 1;
    }

    if ran > 0 {
        info!("Applied {} new migration(s)", ran);
    } else {
        info!("All migrations up to date");
    }

    Ok(())
}

// --- Scan lifecycle ---

pub async fn create_scan(db: &Db, subnet: &str, interface: &str) -> Result<String> {
    #[derive(Debug, Deserialize)]
    struct ScanId {
        id: String,
    }

    let result: Option<ScanId> = db
        .query(
            "
            CREATE scan CONTENT {
                started_at: $now,
                finished_at: NONE,
                subnet: $subnet,
                interface: $interface,
                status: 'running',
                device_count: NONE,
                new_count: NONE,
                updated_count: NONE,
                failed_count: NONE
            } RETURN record::id(id) AS id
            ",
        )
        .bind(("now", Datetime::from(Utc::now())))
        .bind(("subnet", subnet.to_string()))
        .bind(("interface", interface.to_string()))
        .await?
        .take(0)?;

    let scan_id = result
        .map(|r| r.id)
        .ok_or_else(|| anyhow::anyhow!("CREATE scan returned no ID"))?;

    info!("Created scan {}", scan_id);
    Ok(scan_id)
}

pub async fn complete_scan(
    db: &Db,
    scan_id: &str,
    device_count: i32,
    summary: &UpsertSummary,
) -> Result<()> {
    db.query(
        "
        UPDATE type::thing('scan', $scan_id) SET
            finished_at = $now,
            status = 'completed',
            device_count = $device_count,
            new_count = $new_count,
            updated_count = $updated_count,
            failed_count = $failed_count
        ",
    )
    .bind(("scan_id", scan_id.to_string()))
    .bind(("now", Datetime::from(Utc::now())))
    .bind(("device_count", device_count))
    .bind(("new_count", summary.new_count as i32))
    .bind(("updated_count", summary.updated_count as i32))
    .bind(("failed_count", summary.failed_count as i32))
    .await?;

    info!(
        "Scan {} completed: {} devices ({} new, {} updated, {} failed)",
        scan_id, device_count, summary.new_count, summary.updated_count, summary.failed_count
    );
    Ok(())
}

pub async fn fail_scan(db: &Db, scan_id: &str) -> Result<()> {
    db.query(
        "
        UPDATE type::thing('scan', $scan_id) SET
            finished_at = $now,
            status = 'failed'
        ",
    )
    .bind(("scan_id", scan_id.to_string()))
    .bind(("now", Datetime::from(Utc::now())))
    .await?;

    info!("Scan {} marked as failed", scan_id);
    Ok(())
}

pub async fn store_scan_results(
    db: &Db,
    scan_id: &str,
    results: &[IndividualResult],
) -> Result<()> {
    for r in results {
        let _: Option<ScanResultData> = db
            .create("scan_result")
            .content(ScanResultData {
                scan_id: scan_id.to_string(),
                ip: r.ip.clone(),
                mac: r.mac.clone(),
                status: r.status.clone(),
                error: r.error.clone(),
            })
            .await?;
    }
    Ok(())
}

// --- Device upsert ---

pub async fn upsert_scan_results(db: &Db, results: Vec<ArpResult>) -> Result<UpsertSummary> {
    let mut new_count = 0u32;
    let mut updated_count = 0u32;
    let mut failed_count = 0u32;
    let mut individual = Vec::new();

    for result in &results {
        match upsert_device(db, &result.ip, &result.mac).await {
            Ok(true) => {
                new_count += 1;
                info!("[OK] NEW device: {} ({})", result.mac, result.ip);
                individual.push(IndividualResult {
                    ip: result.ip.clone(),
                    mac: result.mac.clone(),
                    status: "new".into(),
                    error: None,
                });
            }
            Ok(false) => {
                updated_count += 1;
                info!("[OK] UPDATED device: {} ({})", result.mac, result.ip);
                individual.push(IndividualResult {
                    ip: result.ip.clone(),
                    mac: result.mac.clone(),
                    status: "updated".into(),
                    error: None,
                });
            }
            Err(e) => {
                failed_count += 1;
                log::error!(
                    "[FAIL] upsert failed for {} ({}): {}",
                    result.mac,
                    result.ip,
                    e
                );
                individual.push(IndividualResult {
                    ip: result.ip.clone(),
                    mac: result.mac.clone(),
                    status: "failed".into(),
                    error: Some(e.to_string()),
                });
            }
        }
    }

    info!(
        "Scan batch complete: {} new, {} updated, {} failed out of {} total",
        new_count,
        updated_count,
        failed_count,
        results.len()
    );
    Ok(UpsertSummary {
        new_count,
        updated_count,
        failed_count,
        results: individual,
    })
}

#[derive(Debug, Serialize, Deserialize)]
struct DeviceData {
    ip: String,
    mac: String,
    alias: Option<String>,
    vendor: Option<String>,
    first_seen: Datetime,
    last_seen: Datetime,
}

#[derive(Debug, Serialize, Deserialize)]
struct EventData {
    device_mac: String,
    timestamp: Datetime,
    kind: String,
    detail: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
struct ScanResultData {
    scan_id: String,
    ip: String,
    mac: String,
    status: String,
    error: Option<String>,
}

async fn upsert_device(db: &Db, ip: &str, mac: &str) -> Result<bool> {
    let existing: Option<DeviceData> = db.select(("device", mac)).await?;

    match existing {
        Some(device) => {
            if device.ip != ip {
                let event = EventData {
                    device_mac: mac.to_string(),
                    timestamp: Datetime::from(Utc::now()),
                    kind: "ip_changed".to_string(),
                    detail: Some(format!("{} -> {}", device.ip, ip)),
                };
                let _: Option<EventData> = db.create("event").content(event).await?;
            }

            let updated = DeviceData {
                ip: ip.to_string(),
                mac: mac.to_string(),
                alias: device.alias,
                vendor: device.vendor,
                first_seen: device.first_seen,
                last_seen: Datetime::from(Utc::now()),
            };
            let _: Option<DeviceData> = db.update(("device", mac)).content(updated).await?;

            Ok(false)
        }
        None => {
            let now = Datetime::from(Utc::now());
            let device = DeviceData {
                ip: ip.to_string(),
                mac: mac.to_string(),
                alias: None,
                vendor: None,
                first_seen: now.clone(),
                last_seen: now,
            };

            let created: Option<DeviceData> = db
                .create(("device", mac))
                .content(device)
                .await?;

            if created.is_none() {
                anyhow::bail!("CREATE returned None for device {}", mac);
            }

            let event = EventData {
                device_mac: mac.to_string(),
                timestamp: Datetime::from(Utc::now()),
                kind: "discovered".to_string(),
                detail: None,
            };
            let _: Option<EventData> = db.create("event").content(event).await?;

            Ok(true)
        }
    }
}

// --- Queries ---

pub async fn get_latest_devices(db: &Db, within_minutes: i64) -> Result<Vec<Device>> {
    let devices: Vec<Device> = db
        .query(
            "
            SELECT ip, mac, alias, vendor, first_seen, last_seen FROM device
            WHERE last_seen > time::now() - <duration>$within
            ORDER BY last_seen DESC
            ",
        )
        .bind(("within", format!("{}m", within_minutes)))
        .await?
        .take(0)?;
    Ok(devices)
}

pub async fn get_device_history(db: &Db, mac: &str) -> Result<Vec<HistoryEvent>> {
    let events: Vec<HistoryEvent> = db
        .query(
            "
            SELECT device_mac, timestamp, kind, detail FROM event
            WHERE device_mac = $mac
            ORDER BY timestamp DESC
            ",
        )
        .bind(("mac", mac.to_string()))
        .await?
        .take(0)?;
    Ok(events)
}

pub async fn get_scans(db: &Db, limit: i64, offset: i64) -> Result<Vec<Scan>> {
    let scans: Vec<Scan> = db
        .query(
            "
            SELECT
                record::id(id) AS id,
                started_at,
                finished_at,
                subnet,
                interface,
                status,
                device_count,
                new_count,
                updated_count,
                failed_count
            FROM scan
            ORDER BY started_at DESC
            LIMIT $limit START $offset
            ",
        )
        .bind(("limit", limit))
        .bind(("offset", offset))
        .await?
        .take(0)?;
    Ok(scans)
}

pub async fn get_scan(db: &Db, id: &str) -> Result<Option<Scan>> {
    let scan: Option<Scan> = db
        .query(
            "
            SELECT
                record::id(id) AS id,
                started_at,
                finished_at,
                subnet,
                interface,
                status,
                device_count,
                new_count,
                updated_count,
                failed_count
            FROM type::thing('scan', $id)
            ",
        )
        .bind(("id", id.to_string()))
        .await?
        .take(0)?;
    Ok(scan)
}

pub async fn get_scan_results(db: &Db, scan_id: &str) -> Result<Vec<ScanResult>> {
    let results: Vec<ScanResult> = db
        .query(
            "
            SELECT
                record::id(id) AS id,
                scan_id,
                ip,
                mac,
                status,
                error
            FROM scan_result
            WHERE scan_id = $scan_id
            ORDER BY mac
            ",
        )
        .bind(("scan_id", scan_id.to_string()))
        .await?
        .take(0)?;
    Ok(results)
}
