use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};

use sea_orm::{ConnectionTrait, DatabaseConnection, sea_query::Query};
use tera::Tera;

use crate::i18n::I18n;

#[derive(Clone)]
pub struct AppResources {
    db: DatabaseConnection,
    tera: Arc<Tera>,
    i18n: I18n,
    database_healthy: Arc<AtomicBool>,
}

impl AppResources {
    pub fn new(db: DatabaseConnection, tera: Arc<Tera>, i18n: I18n) -> Self {
        Self {
            db,
            tera,
            i18n,
            database_healthy: Arc::new(AtomicBool::new(true)),
        }
    }

    #[must_use]
    pub fn db(&self) -> &DatabaseConnection {
        &self.db
    }

    pub async fn ping_database(&self) -> bool {
        self.db
            .execute(&Query::select().expr(1).to_owned())
            .await
            .is_ok()
    }

    pub fn swap_database_healthy(&self, healthy: bool) -> bool {
        self.database_healthy.swap(healthy, Ordering::Relaxed)
    }

    #[must_use]
    pub fn tera(&self) -> &Tera {
        self.tera.as_ref()
    }

    #[must_use]
    pub fn i18n(&self) -> &I18n {
        &self.i18n
    }
}
