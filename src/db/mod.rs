pub mod repo;

use anyhow::Result;
use sea_orm::{ConnectOptions, Database, DatabaseConnection};
use sea_orm_migration::MigratorTrait;

/// Connect to the database described by `url` (e.g. `sqlite:///var/lib/netarp/netarp.db?mode=rwc`)
/// and bring migrations up to date. sqlx's SQLite defaults apply (WAL journal,
/// foreign keys on modern sqlx releases).
pub async fn connect_and_migrate(url: &str) -> Result<DatabaseConnection> {
    let mut opts = ConnectOptions::new(url);
    opts.sqlx_logging(false);

    let db = Database::connect(opts)
        .await
        .map_err(|e| anyhow::anyhow!("connect {url}: {e}"))?;

    netarp_migration::Migrator::up(&db, None).await?;
    log::info!("Database ready ({url})");
    Ok(db)
}
