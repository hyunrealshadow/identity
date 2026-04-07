use std::sync::Arc;

use sea_orm::DatabaseConnection;
use tera::Tera;

use crate::infrastructure::i18n::I18n;

#[derive(Clone)]
pub struct AppResources {
    db: DatabaseConnection,
    tera: Arc<Tera>,
    i18n: I18n,
}

impl AppResources {
    pub fn new(db: DatabaseConnection, tera: Arc<Tera>, i18n: I18n) -> Self {
        Self { db, tera, i18n }
    }

    #[must_use]
    pub fn db(&self) -> &DatabaseConnection {
        &self.db
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
