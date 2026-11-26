use std::time::Duration;

use sea_orm::{
    ConnectOptions, ConnectionTrait, Database, DatabaseConnection, DbErr,
    sea_query::{Alias, Func, Query},
};

use crate::config::DatabaseConfig;

const INSTALL_ADVISORY_LOCK_KEY: i64 = 841_463_791_178_241_511;

/// Holds a dedicated single-connection database session owning the PostgreSQL
/// installation advisory lock until dropped.
pub struct InstallLockGuard {
    _connection: DatabaseConnection,
}

impl std::fmt::Debug for InstallLockGuard {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("InstallLockGuard")
            .finish_non_exhaustive()
    }
}

/// Acquire the PostgreSQL session advisory lock on a dedicated connection so
/// pooled queries cannot release or lose the lock.
pub async fn try_acquire_install_lock(
    config: &DatabaseConfig,
) -> Result<Option<InstallLockGuard>, DbErr> {
    let mut options = ConnectOptions::new(config.uri.clone());
    options.sqlx_logging(config.enable_logging);
    options.connect_timeout(Duration::from_millis(config.connect_timeout));
    options.min_connections(1);
    options.max_connections(1);

    let connection = Database::connect(options).await?;
    let statement = Query::select()
        .expr_as(
            Func::cust("pg_try_advisory_lock").arg(INSTALL_ADVISORY_LOCK_KEY),
            Alias::new("acquired"),
        )
        .to_owned();

    let acquired = match connection.query_one(&statement).await {
        Ok(Some(row)) => row.try_get::<bool>("", "acquired")?,
        Ok(None) => false,
        Err(error) => {
            let _ = connection.close().await;
            return Err(error);
        }
    };

    if acquired {
        Ok(Some(InstallLockGuard {
            _connection: connection,
        }))
    } else {
        let _ = connection.close().await;
        Ok(None)
    }
}
