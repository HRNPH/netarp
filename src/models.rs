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
