use std::time::Duration;

use apalis_sql::{postgres::PostgresStorage, sqlx};

use crate::{config::AppConfig, state::AppState};

pub mod authorization_expiration;
pub mod rotation;

pub async fn spawn_background_workers(
    state: AppState,
    config: &AppConfig,
) -> Result<(), sqlx::Error> {
    // Apalis SQL 0.7 uses SQLx 0.8 while SeaORM 2 uses SQLx 0.9, so the
    // backends connect to the same database through separate pools.
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(5)
        .acquire_timeout(Duration::from_millis(config.database.connect_timeout))
        .connect(&config.database.uri)
        .await?;
    if config.database.auto_migrate {
        PostgresStorage::<()>::setup(&pool).await?;
    }

    rotation::spawn_rotation_workers(state.clone(), pool.clone()).await?;
    authorization_expiration::spawn_expiration_workers(state, pool).await?;
    Ok(())
}
