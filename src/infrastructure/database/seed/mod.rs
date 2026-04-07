use std::error::Error;

use async_trait::async_trait;
use sea_orm::DatabaseConnection;

use crate::{
    application::error::AppError,
    infrastructure::{config::AppConfig, database},
};

type SeedResult<T> = Result<T, Box<dyn Error + Send + Sync + 'static>>;

#[async_trait]
pub trait Seed: Send + Sync {
    fn name(&self) -> &'static str;

    async fn run(&self, db: &DatabaseConnection) -> Result<(), AppError>;
}

pub async fn run_all(db: &DatabaseConnection) -> Result<(), AppError> {
    let seeds: Vec<Box<dyn Seed>> = Vec::new();

    for seed in seeds {
        seed.run(db).await?;
        tracing::info!(seed = seed.name(), "seed ensured");
    }

    Ok(())
}

pub async fn run_all_from_config() -> SeedResult<()> {
    let (config, _) = AppConfig::load()?;
    let db = database::connect(&config.database).await?;

    if config.database.auto_migrate {
        database::migrate(&db).await?;
    }

    run_all(&db).await.map_err(Into::into)
}
