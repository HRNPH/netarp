use anyhow::Result;
use log::info;
use surrealdb::engine::local::RocksDb;
use surrealdb::Surreal;

use crate::models::{ArpResult, Device, HistoryEvent};

pub type Db = Surreal<surrealdb::engine::local::Db>;

pub async fn init_db(path: &str) -> Result<Db> {
    let db = Surreal::new::<RocksDb>(path).await?;
    db.use_ns("netarp").use_db("network").await?;

    db.query(
        "
        DEFINE TABLE device SCHEMAFULL;
        DEFINE FIELD ip ON device TYPE string;
        DEFINE FIELD mac ON device TYPE string;
        DEFINE FIELD alias ON device TYPE option<string>;
        DEFINE FIELD vendor ON device TYPE option<string>;
        DEFINE FIELD first_seen ON device TYPE datetime;
        DEFINE FIELD last_seen ON device TYPE datetime;

        DEFINE TABLE event SCHEMAFULL;
        DEFINE FIELD device_mac ON event TYPE string;
        DEFINE FIELD timestamp ON event TYPE datetime;
        DEFINE FIELD kind ON event TYPE string;
        DEFINE FIELD detail ON event TYPE option<string>;

        DEFINE INDEX idx_device_mac ON device COLUMNS mac;
        DEFINE INDEX idx_event_mac ON event COLUMNS device_mac;
        DEFINE INDEX idx_event_ts ON event COLUMNS timestamp;
        ",
    )
    .await?;

    info!("Database initialized at {}", path);
    Ok(db)
}

pub async fn upsert_scan_results(db: &Db, results: Vec<ArpResult>) -> Result<()> {
    for result in results {
        upsert_device(db, &result.ip, &result.mac).await?;
    }
    Ok(())
}

async fn upsert_device(db: &Db, ip: &str, mac: &str) -> Result<()> {
    let existing: Option<Device> = db.select(("device", mac)).await?;

    match existing {
        Some(device) => {
            if device.ip != ip {
                db.query(
                    "
                    CREATE event SET
                        device_mac = $mac,
                        timestamp = time::now(),
                        kind = 'ip_changed',
                        detail = $detail
                    ",
                )
                .bind(("mac", mac.to_string()))
                .bind(("detail", format!("{} -> {}", device.ip, ip)))
                .await?;
            }
            db.query(
                "
                UPDATE type::thing('device', $mac) SET
                    ip = $ip,
                    last_seen = time::now()
                ",
            )
            .bind(("mac", mac.to_string()))
            .bind(("ip", ip.to_string()))
            .await?;
        }
        None => {
            db.query(
                "
                UPDATE type::thing('device', $mac) SET
                    ip = $ip,
                    mac = $mac,
                    first_seen = time::now(),
                    last_seen = time::now()
                ",
            )
            .bind(("mac", mac.to_string()))
            .bind(("ip", ip.to_string()))
            .await?;

            db.query(
                "
                CREATE event SET
                    device_mac = $mac,
                    timestamp = time::now(),
                    kind = 'discovered'
                ",
            )
            .bind(("mac", mac.to_string()))
            .await?;
        }
    }

    Ok(())
}

pub async fn get_latest_devices(db: &Db, within_minutes: i64) -> Result<Vec<Device>> {
    let devices: Vec<Device> = db
        .query(
            "
            SELECT * FROM device
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
            SELECT * FROM event
            WHERE device_mac = $mac
            ORDER BY timestamp DESC
            ",
        )
        .bind(("mac", mac.to_string()))
        .await?
        .take(0)?;
    Ok(events)
}
