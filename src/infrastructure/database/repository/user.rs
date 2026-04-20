use async_trait::async_trait;
use chrono::{DateTime, Utc};
use sea_orm::{
    ColumnTrait, DatabaseConnection, EntityTrait, ExprTrait, QueryFilter, sea_query::Expr,
};

use crate::domain::user::{
    User, UserOid,
    repository::{UserRepository, UserRepositoryError},
};
use crate::infrastructure::database::entity::{user, user::Entity as UserEntity};

fn to_domain(m: user::Model) -> User {
    User {
        oid: m.oid.into(),
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

    async fn find_by_oid(&self, oid: UserOid) -> Result<Option<User>, UserRepositoryError> {
        let model = UserEntity::find()
            .filter(user::Column::Oid.eq(uuid::Uuid::from(oid)))
            .one(&self.db)
            .await
            .map_err(UserRepositoryError::QueryFailed)?;
        Ok(model.map(to_domain))
    }

    async fn increment_failed_attempts(
        &self,
        user_oid: UserOid,
        lock_until: Option<DateTime<Utc>>,
    ) -> Result<(), UserRepositoryError> {
        let oid = uuid::Uuid::from(user_oid);
        let now = Utc::now().naive_utc();
        let mut update = UserEntity::update_many()
            .col_expr(
                user::Column::FailedAttempts,
                Expr::col(user::Column::FailedAttempts).add(1),
            )
            .col_expr(
                user::Column::UpdatedAt,
                Expr::value(Option::<chrono::NaiveDateTime>::Some(now)),
            )
            .filter(user::Column::Oid.eq(oid));

        if let Some(until) = lock_until {
            update = update
                .col_expr(user::Column::Locked, Expr::value(true))
                .col_expr(
                    user::Column::LockedUntil,
                    Expr::value(Option::<chrono::NaiveDateTime>::Some(until.naive_utc())),
                );
        }

        update
            .exec(&self.db)
            .await
            .map_err(UserRepositoryError::UpdateFailedAttempts)?;
        Ok(())
    }

    async fn reset_failed_attempts(&self, user_oid: UserOid) -> Result<(), UserRepositoryError> {
        let oid = uuid::Uuid::from(user_oid);
        UserEntity::update_many()
            .col_expr(user::Column::FailedAttempts, Expr::value(0i32))
            .col_expr(user::Column::Locked, Expr::value(false))
            .col_expr(
                user::Column::LockedUntil,
                Expr::value(Option::<chrono::NaiveDateTime>::None),
            )
            .col_expr(
                user::Column::UpdatedAt,
                Expr::value(Option::<chrono::NaiveDateTime>::Some(
                    Utc::now().naive_utc(),
                )),
            )
            .filter(user::Column::Oid.eq(oid))
            .exec(&self.db)
            .await
            .map_err(UserRepositoryError::ResetFailedAttempts)?;
        Ok(())
    }
}
