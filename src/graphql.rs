use async_graphql::{Context, EmptyMutation, EmptySubscription, Object, Schema};
use async_graphql_axum::{GraphQLRequest, GraphQLResponse};
use axum::response::Html;
use axum::Extension;

use crate::db::{self, Db};
use crate::models::{Device, HistoryEvent, Scan, ScanResult};

pub type AppSchema = Schema<Query, EmptyMutation, EmptySubscription>;

pub fn create_schema(db: Db) -> AppSchema {
    Schema::build(Query, EmptyMutation, EmptySubscription)
        .data(db)
        .finish()
}

pub struct Query;

#[Object]
impl Query {
    async fn latest_devices(
        &self,
        ctx: &Context<'_>,
        #[graphql(desc = "Minutes to look back (default 10)")] within_minutes: Option<i64>,
    ) -> async_graphql::Result<Vec<Device>> {
        let db = ctx.data::<Db>()?;
        let minutes = within_minutes.unwrap_or(10);
        let devices = db::get_latest_devices(db, minutes).await?;
        Ok(devices)
    }

    async fn device_history(
        &self,
        ctx: &Context<'_>,
        #[graphql(desc = "MAC address of the device")] mac: String,
    ) -> async_graphql::Result<Vec<HistoryEvent>> {
        let db = ctx.data::<Db>()?;
        let events = db::get_device_history(db, &mac).await?;
        Ok(events)
    }

    async fn all_devices(&self, ctx: &Context<'_>) -> async_graphql::Result<Vec<Device>> {
        let db = ctx.data::<Db>()?;
        let devices: Vec<Device> = db
            .query("SELECT ip, mac, alias, vendor, first_seen, last_seen FROM device ORDER BY last_seen DESC")
            .await?
            .take(0)?;
        Ok(devices)
    }

    async fn scans(
        &self,
        ctx: &Context<'_>,
        #[graphql(desc = "Max results (default 20)")] limit: Option<i64>,
        #[graphql(desc = "Offset for pagination")] offset: Option<i64>,
    ) -> async_graphql::Result<Vec<Scan>> {
        let db = ctx.data::<Db>()?;
        let scans = db::get_scans(db, limit.unwrap_or(20), offset.unwrap_or(0)).await?;
        Ok(scans)
    }

    async fn scan(
        &self,
        ctx: &Context<'_>,
        #[graphql(desc = "Scan record ID")] id: String,
    ) -> async_graphql::Result<Option<Scan>> {
        let db = ctx.data::<Db>()?;
        let scan = db::get_scan(db, &id).await?;
        Ok(scan)
    }

    async fn scan_results(
        &self,
        ctx: &Context<'_>,
        #[graphql(desc = "Scan ID to get results for")] scan_id: String,
    ) -> async_graphql::Result<Vec<ScanResult>> {
        let db = ctx.data::<Db>()?;
        let results = db::get_scan_results(db, &scan_id).await?;
        Ok(results)
    }
}

pub async fn graphql_handler(
    Extension(schema): Extension<AppSchema>,
    req: GraphQLRequest,
) -> GraphQLResponse {
    schema.execute(req.into_inner()).await.into()
}

pub async fn graphql_playground() -> Html<String> {
    Html(async_graphql::http::playground_source(
        async_graphql::http::GraphQLPlaygroundConfig::new("/graphql"),
    ))
}
