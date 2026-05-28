use std::io;

use sea_orm::{
    ConnectionTrait, DatabaseConnection,
    sea_query::{Alias, Expr, Query},
};

use identity_application::setting::runtime::SettingProvider;
use identity_infrastructure::settings::AppRuntimeSettings;

use super::AppResult;

pub async fn ensure_install_startup_guard(
    db: &DatabaseConnection,
    settings: &AppRuntimeSettings,
) -> AppResult<()> {
    if *settings.installation_initialized().current_value() {
        return Ok(());
    }

    if try_acquire_install_lock(db).await? {
        tracing::info!("installation lock acquired for this instance");
        return Ok(());
    }

    settings.installation().refresh().await?;
    if *settings.installation_initialized().current_value() {
        return Ok(());
    }

    Err(Box::new(io::Error::other(
        "installation is in progress on another pod; refusing startup",
    )))
}

async fn try_acquire_install_lock(db: &DatabaseConnection) -> AppResult<bool> {
    let statement = Query::select()
        .expr_as(
            Expr::cust("pg_try_advisory_lock(841463791178241511)"),
            Alias::new("acquired"),
        )
        .to_owned();

    let row = db
        .query_one(&statement)
        .await?
        .ok_or_else(|| io::Error::other("failed to query installation lock state"))?;

    row.try_get("", "acquired").map_err(|error| {
        Box::new(io::Error::other(error.to_string())) as Box<dyn std::error::Error + Send + Sync>
    })
}
