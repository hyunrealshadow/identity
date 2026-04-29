use std::time::Duration;

use migration::{DbErr, Migrator, MigratorTrait};
use sea_orm::{ConnectOptions, Database, DatabaseConnection};

use crate::config::DatabaseConfig;

pub mod entity;
pub mod repository;
pub mod seed;

pub async fn connect(config: &DatabaseConfig) -> Result<DatabaseConnection, sea_orm::DbErr> {
    let mut options = ConnectOptions::new(config.uri.clone());
    options.sqlx_logging(config.enable_logging);
    options.connect_timeout(Duration::from_millis(config.connect_timeout));
    options.idle_timeout(Duration::from_millis(config.idle_timeout));
    options.min_connections(config.min_connections);
    options.max_connections(config.max_connections);

    Database::connect(options).await
}

pub async fn migrate(db: &DatabaseConnection) -> Result<(), DbErr> {
    Migrator::up(db, None).await
}
