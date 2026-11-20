use async_graphql::{Context, EmptyMutation, EmptySubscription, Object, Schema};
use async_graphql_axum::{GraphQLRequest, GraphQLResponse};
use axum::Extension;
use axum::response::Html;
use sea_orm::DatabaseConnection;

use crate::db::repo;
use crate::models::{Device, HistoryEvent, Scan, ScanResult};

pub type DbSchema = Schema<Query, EmptyMutation, EmptySubscription>;

pub fn create_schema(db: DatabaseConnection) -> DbSchema {
    Schema::build(Query, EmptyMutation, EmptySubscription)
        .data(db)
        .finish()
}

pub struct Query;

#[Object]
impl Query {
    /// Devices seen within the last N minutes
    async fn latest_devices(&self, ctx: &Context<'_>, within_minutes: Option<i64>) -> Vec<Device> {
        let db = ctx.data::<DatabaseConnection>().unwrap();
        repo::get_latest_devices(db, within_minutes.unwrap_or(10))
            .await
            .unwrap_or_default()
    }

    /// All known devices
    async fn all_devices(&self, ctx: &Context<'_>) -> Vec<Device> {
        let db = ctx.data::<DatabaseConnection>().unwrap();
        repo::get_all_devices(db).await.unwrap_or_default()
    }

    /// Event history for one device (by MAC)
    async fn device_history(&self, ctx: &Context<'_>, mac: String) -> Vec<HistoryEvent> {
        let db = ctx.data::<DatabaseConnection>().unwrap();
        repo::get_device_history(db, &mac).await.unwrap_or_default()
    }

    /// Recent scans
    async fn scans(&self, ctx: &Context<'_>, limit: Option<u64>, offset: Option<u64>) -> Vec<Scan> {
        let db = ctx.data::<DatabaseConnection>().unwrap();
        repo::get_scans(db, limit.unwrap_or(20), offset.unwrap_or(0))
            .await
            .unwrap_or_default()
    }

    /// One scan by id
    async fn scan(&self, ctx: &Context<'_>, id: i32) -> Option<Scan> {
        let db = ctx.data::<DatabaseConnection>().unwrap();
        repo::get_scan(db, id).await.ok().flatten()
    }

    /// Per-device results of one scan
    async fn scan_results(&self, ctx: &Context<'_>, scan_id: i32) -> Vec<ScanResult> {
        let db = ctx.data::<DatabaseConnection>().unwrap();
        repo::get_scan_results(db, scan_id)
            .await
            .unwrap_or_default()
    }
}

pub async fn graphql_handler(
    Extension(schema): Extension<DbSchema>,
    req: GraphQLRequest,
) -> GraphQLResponse {
    schema.execute(req.into_inner()).await.into()
}

pub async fn graphql_playground() -> Html<String> {
    Html(async_graphql::http::playground_source(
        async_graphql::http::GraphQLPlaygroundConfig::new("/graphql"),
    ))
}
