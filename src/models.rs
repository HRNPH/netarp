use async_graphql::SimpleObject;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, SimpleObject)]
pub struct Device {
    pub ip: String,
    pub mac: String,
    pub alias: Option<String>,
    pub vendor: Option<String>,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, SimpleObject)]
pub struct HistoryEvent {
    pub device_mac: String,
    pub timestamp: DateTime<Utc>,
    pub kind: String,
    pub detail: Option<String>,
}

#[derive(Debug, Clone)]
pub struct ArpResult {
    pub ip: String,
    pub mac: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, SimpleObject)]
pub struct Scan {
    pub id: String,
    pub started_at: DateTime<Utc>,
    pub finished_at: Option<DateTime<Utc>>,
    pub subnet: String,
    pub interface: String,
    pub status: String,
    pub device_count: Option<i32>,
    pub new_count: Option<i32>,
    pub updated_count: Option<i32>,
    pub failed_count: Option<i32>,
}

#[derive(Debug, Clone, Serialize, Deserialize, SimpleObject)]
pub struct ScanResult {
    pub id: String,
    pub scan_id: String,
    pub ip: String,
    pub mac: String,
    pub status: String,
    pub error: Option<String>,
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
