use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[cfg(feature = "graphql")]
use async_graphql::SimpleObject;

use crate::entity::{device, event, scan, scan_result};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "graphql", derive(SimpleObject))]
pub struct Device {
    pub ip: String,
    pub mac: String,
    pub alias: Option<String>,
    pub vendor: Option<String>,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
}

impl From<device::Model> for Device {
    fn from(m: device::Model) -> Self {
        Self {
            ip: m.ip,
            mac: m.mac,
            alias: m.alias,
            vendor: m.vendor,
            first_seen: m.first_seen,
            last_seen: m.last_seen,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "graphql", derive(SimpleObject))]
pub struct HistoryEvent {
    pub device_mac: String,
    pub timestamp: DateTime<Utc>,
    pub kind: String,
    pub detail: Option<String>,
}

impl From<event::Model> for HistoryEvent {
    fn from(m: event::Model) -> Self {
        Self {
            device_mac: m.device_mac,
            timestamp: m.timestamp,
            kind: m.kind,
            detail: m.detail,
        }
    }
}

#[derive(Debug, Clone)]
pub struct ArpResult {
    pub ip: String,
    pub mac: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "graphql", derive(SimpleObject))]
pub struct Scan {
    pub id: i32,
    pub started_at: DateTime<Utc>,
    pub finished_at: Option<DateTime<Utc>>,
    pub subnets: String,
    pub interface: String,
    pub status: String,
    pub device_count: Option<i32>,
    pub new_count: Option<i32>,
    pub updated_count: Option<i32>,
    pub failed_count: Option<i32>,
}

impl From<scan::Model> for Scan {
    fn from(m: scan::Model) -> Self {
        Self {
            id: m.id,
            started_at: m.started_at,
            finished_at: m.finished_at,
            subnets: m.subnets,
            interface: m.interface,
            status: m.status,
            device_count: m.device_count,
            new_count: m.new_count,
            updated_count: m.updated_count,
            failed_count: m.failed_count,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "graphql", derive(SimpleObject))]
pub struct ScanResult {
    pub id: i32,
    pub scan_id: i32,
    pub ip: String,
    pub mac: String,
    pub status: String,
    pub error: Option<String>,
}

impl From<scan_result::Model> for ScanResult {
    fn from(m: scan_result::Model) -> Self {
        Self {
            id: m.id,
            scan_id: m.scan_id,
            ip: m.ip,
            mac: m.mac,
            status: m.status,
            error: m.error,
        }
    }
}

#[derive(Debug, Clone)]
pub struct UpsertSummary {
    pub new_count: u32,
    pub updated_count: u32,
    pub failed_count: u32,
    pub results: Vec<IndividualResult>,
}

#[derive(Debug, Clone)]
pub struct IndividualResult {
    pub ip: String,
    pub mac: String,
    pub status: String,
    pub error: Option<String>,
}
