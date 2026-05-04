use async_graphql::{Context, EmptyMutation, EmptySubscription, Object, Schema};
use async_graphql_axum::{GraphQLRequest, GraphQLResponse};
use axum::response::Html;
use axum::Extension;

use crate::db::{self, Db};
use crate::models::{Device, HistoryEvent};

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
