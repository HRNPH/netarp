use anyhow::Result;
use chrono::Utc;
use sea_orm::sea_query::Expr;
use sea_orm::*;

use crate::entity::{device, event, scan, scan_result};
use crate::models::{Device, HistoryEvent, IndividualResult, Scan, ScanResult, UpsertSummary};
use crate::names::AliasMaps;

// --- Scan lifecycle ---

pub async fn create_scan(db: &DatabaseConnection, subnets: &str, interface: &str) -> Result<i32> {
    let row = scan::ActiveModel {
        started_at: Set(Utc::now()),
        finished_at: Set(None),
        subnets: Set(subnets.to_string()),
        interface: Set(interface.to_string()),
        status: Set("running".to_string()),
        device_count: Set(None),
        new_count: Set(None),
        updated_count: Set(None),
        failed_count: Set(None),
        ..Default::default()
    };
    let row = row.insert(db).await?;
    log::info!("Created scan {}", row.id);
    Ok(row.id)
}

pub async fn complete_scan(
    db: &DatabaseConnection,
    scan_id: i32,
    device_count: i32,
    summary: &UpsertSummary,
) -> Result<()> {
    scan::Entity::update_many()
        .col_expr(scan::Column::FinishedAt, Expr::value(Utc::now()))
        .col_expr(scan::Column::Status, Expr::value("completed"))
        .col_expr(scan::Column::DeviceCount, Expr::value(device_count))
        .col_expr(
            scan::Column::NewCount,
            Expr::value(summary.new_count as i32),
        )
        .col_expr(
            scan::Column::UpdatedCount,
            Expr::value(summary.updated_count as i32),
        )
        .col_expr(
            scan::Column::FailedCount,
            Expr::value(summary.failed_count as i32),
        )
        .filter(scan::Column::Id.eq(scan_id))
        .exec(db)
        .await?;
    log::info!(
        "Scan {} completed: {} devices ({} new, {} updated, {} failed)",
        scan_id,
        device_count,
        summary.new_count,
        summary.updated_count,
        summary.failed_count
    );
    Ok(())
}

pub async fn fail_scan(db: &DatabaseConnection, scan_id: i32) -> Result<()> {
    scan::Entity::update_many()
        .col_expr(scan::Column::FinishedAt, Expr::value(Utc::now()))
        .col_expr(scan::Column::Status, Expr::value("failed"))
        .filter(scan::Column::Id.eq(scan_id))
        .exec(db)
        .await?;
    log::info!("Scan {} marked as failed", scan_id);
    Ok(())
}

pub async fn store_scan_results(
    db: &DatabaseConnection,
    scan_id: i32,
    results: &[IndividualResult],
) -> Result<()> {
    let rows: Vec<scan_result::ActiveModel> = results
        .iter()
        .map(|r| scan_result::ActiveModel {
            scan_id: Set(scan_id),
            ip: Set(r.ip.clone()),
            mac: Set(r.mac.clone()),
            status: Set(r.status.clone()),
            error: Set(r.error.clone()),
            ..Default::default()
        })
        .collect();
    if rows.is_empty() {
        return Ok(());
    }
    scan_result::Entity::insert_many(rows).exec(db).await?;
    Ok(())
}

// --- Device upsert ---

/// Upsert every discovered (ip, mac). Returns the summary plus the resulting
/// device rows (post-update), so callers can forward them to exports.
pub async fn upsert_scan_results(
    db: &DatabaseConnection,
    results: Vec<crate::models::ArpResult>,
    aliases: &AliasMaps,
) -> Result<(UpsertSummary, Vec<device::Model>)> {
    let mut new_count = 0u32;
    let mut updated_count = 0u32;
    let mut failed_count = 0u32;
    let mut individual = Vec::new();
    let mut devices = Vec::new();

    for result in &results {
        match upsert_device(db, &result.ip, &result.mac, aliases).await {
            Ok((is_new, model)) => {
                if is_new {
                    new_count += 1;
                    log::info!("[OK] NEW device: {} ({})", result.mac, result.ip);
                    individual.push(IndividualResult {
                        ip: result.ip.clone(),
                        mac: result.mac.clone(),
                        status: "new".into(),
                        error: None,
                    });
                } else {
                    updated_count += 1;
                    log::info!("[OK] UPDATED device: {} ({})", result.mac, result.ip);
                    individual.push(IndividualResult {
                        ip: result.ip.clone(),
                        mac: result.mac.clone(),
                        status: "updated".into(),
                        error: None,
                    });
                }
                devices.push(model);
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

    log::info!(
        "Scan batch complete: {} new, {} updated, {} failed out of {} total",
        new_count,
        updated_count,
        failed_count,
        results.len()
    );
    Ok((
        UpsertSummary {
            new_count,
            updated_count,
            failed_count,
            results: individual,
        },
        devices,
    ))
}

/// Insert or refresh one device. Emits `discovered` / `ip_changed` / `alias_set`
/// events. Returns (is_new, current model).
async fn upsert_device(
    db: &DatabaseConnection,
    ip: &str,
    mac: &str,
    aliases: &AliasMaps,
) -> Result<(bool, device::Model)> {
    // MAC match wins (stable identity), IP match as fallback (DNS names).
    let wanted_alias = aliases
        .by_mac
        .get(&mac.to_ascii_lowercase())
        .or_else(|| aliases.by_ip.get(ip))
        .cloned();

    let existing = device::Entity::find_by_id(mac.to_string()).one(db).await?;

    match existing {
        Some(dev) => {
            if dev.ip != ip {
                insert_event(
                    db,
                    mac,
                    "ip_changed",
                    Some(&format!("{} -> {}", dev.ip, ip)),
                )
                .await?;
            }

            let alias_changed = match (&dev.alias, &wanted_alias) {
                (Some(a), Some(b)) => a != b,
                (None, Some(_)) => true,
                _ => false,
            };
            if alias_changed && let Some(new_alias) = &wanted_alias {
                insert_event(db, mac, "alias_set", Some(new_alias)).await?;
            }

            let am = device::ActiveModel {
                mac: sea_orm::Unchanged(mac.to_string()),
                ip: Set(ip.to_string()),
                alias: Set(if alias_changed {
                    wanted_alias
                } else {
                    dev.alias.clone()
                }),
                vendor: sea_orm::Unchanged(dev.vendor.clone()),
                first_seen: sea_orm::Unchanged(dev.first_seen),
                last_seen: Set(Utc::now()),
            };
            let model = am.update(db).await?;
            Ok((false, model))
        }
        None => {
            let now = Utc::now();
            let alias = wanted_alias;
            let model = device::ActiveModel {
                mac: Set(mac.to_string()),
                ip: Set(ip.to_string()),
                alias: Set(alias),
                vendor: Set(None),
                first_seen: Set(now),
                last_seen: Set(now),
            }
            .insert(db)
            .await?;

            insert_event(db, mac, "discovered", None).await?;
            Ok((true, model))
        }
    }
}

async fn insert_event(
    db: &DatabaseConnection,
    device_mac: &str,
    kind: &str,
    detail: Option<&str>,
) -> Result<()> {
    event::ActiveModel {
        device_mac: Set(device_mac.to_string()),
        timestamp: Set(Utc::now()),
        kind: Set(kind.to_string()),
        detail: Set(detail.map(|s| s.to_string())),
        ..Default::default()
    }
    .insert(db)
    .await?;
    Ok(())
}

// --- Queries ---

#[cfg_attr(not(feature = "graphql"), allow(dead_code))]
pub async fn get_latest_devices(
    db: &DatabaseConnection,
    within_minutes: i64,
) -> Result<Vec<Device>> {
    let cutoff = Utc::now() - chrono::Duration::minutes(within_minutes);
    let rows = device::Entity::find()
        .filter(device::Column::LastSeen.gt(cutoff))
        .order_by_desc(device::Column::LastSeen)
        .all(db)
        .await?;
    Ok(rows.into_iter().map(Into::into).collect())
}

#[cfg_attr(not(feature = "graphql"), allow(dead_code))]
pub async fn get_all_devices(db: &DatabaseConnection) -> Result<Vec<Device>> {
    let rows = device::Entity::find()
        .order_by_desc(device::Column::LastSeen)
        .all(db)
        .await?;
    Ok(rows.into_iter().map(Into::into).collect())
}

#[cfg_attr(not(feature = "graphql"), allow(dead_code))]
pub async fn get_device_history(db: &DatabaseConnection, mac: &str) -> Result<Vec<HistoryEvent>> {
    let rows = event::Entity::find()
        .filter(event::Column::DeviceMac.eq(mac))
        .order_by_desc(event::Column::Timestamp)
        .all(db)
        .await?;
    Ok(rows.into_iter().map(Into::into).collect())
}

#[cfg_attr(not(feature = "graphql"), allow(dead_code))]
pub async fn get_scans(db: &DatabaseConnection, limit: u64, offset: u64) -> Result<Vec<Scan>> {
    let rows = scan::Entity::find()
        .order_by_desc(scan::Column::StartedAt)
        .offset(offset)
        .limit(limit)
        .all(db)
        .await?;
    Ok(rows.into_iter().map(Into::into).collect())
}

#[cfg_attr(not(feature = "graphql"), allow(dead_code))]
pub async fn get_scan(db: &DatabaseConnection, id: i32) -> Result<Option<Scan>> {
    let row = scan::Entity::find_by_id(id).one(db).await?;
    Ok(row.map(Into::into))
}

#[cfg_attr(not(feature = "graphql"), allow(dead_code))]
pub async fn get_scan_results(db: &DatabaseConnection, scan_id: i32) -> Result<Vec<ScanResult>> {
    let rows = scan_result::Entity::find()
        .filter(scan_result::Column::ScanId.eq(scan_id))
        .order_by_asc(scan_result::Column::Mac)
        .all(db)
        .await?;
    Ok(rows.into_iter().map(Into::into).collect())
}
