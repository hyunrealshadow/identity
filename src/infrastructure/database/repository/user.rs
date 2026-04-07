use async_trait::async_trait;
use chrono::{DateTime, Utc};
use sea_orm::{ActiveModelTrait, ColumnTrait, DatabaseConnection, EntityTrait, QueryFilter, Set};
use uuid::Uuid;

use crate::domain::user::{
    model::User,
    repository::{UserRepository, UserRepositoryError},
};
use crate::infrastructure::database::entity::{user, user::Entity as UserEntity};

fn to_domain(m: user::Model) -> User {
    User {
        oid: m.oid,
        email: m.email,
        email_normalized: m.email_normalized,
        name: m.name,
        name_normalized: m.name_normalized,
        email_verified: m.email_verified,
        failed_attempts: m.failed_attempts,
        enabled: m.enabled,
        locked: m.locked,
        locked_until: m.locked_until.map(|v| chrono::DateTime::<Utc>::from(v)),
        created_at: DateTime::<Utc>::from(m.created_at),
        updated_at: m.updated_at.map(DateTime::<Utc>::from),
    }
}

pub struct UserRepositoryImpl {
    db: DatabaseConnection,
}

impl UserRepositoryImpl {
    pub fn new(db: DatabaseConnection) -> Self {
        Self { db }
    }
}

#[async_trait]
impl UserRepository for UserRepositoryImpl {
    async fn find_by_identifier(&self, identifier: &str) -> Result<User, UserRepositoryError> {
        use sea_orm::Condition;
        let normalized = identifier.trim().to_lowercase();
        let model = UserEntity::find()
            .filter(
                Condition::any()
                    .add(user::Column::EmailNormalized.eq(&normalized))
                    .add(user::Column::NameNormalized.eq(&normalized)),
            )
            .one(&self.db)
            .await
            .map_err(UserRepositoryError::QueryFailed)?;
        model
            .map(to_domain)
            .ok_or(UserRepositoryError::UserNotFound)
    }

    async fn find_by_oid(&self, oid: Uuid) -> Result<Option<User>, UserRepositoryError> {
        let model = UserEntity::find()
            .filter(user::Column::Oid.eq(oid))
            .one(&self.db)
            .await
            .map_err(UserRepositoryError::QueryFailed)?;
        Ok(model.map(to_domain))
    }

    async fn increment_failed_attempts(
        &self,
        user_oid: Uuid,
        lock_until: Option<DateTime<Utc>>,
    ) -> Result<(), UserRepositoryError> {
        let model = UserEntity::find()
            .filter(user::Column::Oid.eq(user_oid))
            .one(&self.db)
            .await
            .map_err(UserRepositoryError::QueryFailed)?
            .ok_or(UserRepositoryError::UserNotFound)?;

        let new_attempts = model.failed_attempts + 1;
        let mut active: user::ActiveModel = model.into();
        active.failed_attempts = Set(new_attempts);
        if let Some(until) = lock_until {
            active.locked = Set(true);
            active.locked_until = Set(Some(until.into()));
        }
        active.updated_at = Set(Some(Utc::now().into()));
        active
            .update(&self.db)
            .await
            .map_err(UserRepositoryError::UpdateFailedAttempts)?;
        Ok(())
    }

    async fn reset_failed_attempts(&self, user_oid: Uuid) -> Result<(), UserRepositoryError> {
        let model = UserEntity::find()
            .filter(user::Column::Oid.eq(user_oid))
            .one(&self.db)
            .await
            .map_err(UserRepositoryError::QueryFailed)?
            .ok_or(UserRepositoryError::UserNotFound)?;

        let mut active: user::ActiveModel = model.into();
        active.failed_attempts = Set(0);
        active.locked = Set(false);
        active.locked_until = Set(None);
        active.updated_at = Set(Some(Utc::now().into()));
        active
            .update(&self.db)
            .await
            .map_err(UserRepositoryError::ResetFailedAttempts)?;
        Ok(())
    }
}
