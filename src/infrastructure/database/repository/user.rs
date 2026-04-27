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
        given_name: m.given_name,
        family_name: m.family_name,
        middle_name: m.middle_name,
        nickname: m.nickname,
        profile: m.profile,
        picture: m.picture,
        website: m.website,
        gender: m.gender,
        birthdate: m.birthdate,
        zoneinfo: m.zone_info,
        locale: m.locale,
        email_verified: m.email_verified,
        phone_number: m.phone_number,
        phone_number_verified: m.phone_number_verified,
        address_formatted: m.address_formatted,
        address_street_address: m.address_street_address,
        address_locality: m.address_locality,
        address_region: m.address_region,
        address_postal_code: m.address_postal_code,
        address_country: m.address_country,
        failed_attempts: m.failed_attempts,
        enabled: m.enabled,
        locked: m.locked,
        locked_until: m.locked_until.map(|v| chrono::DateTime::<Utc>::from(v)),
        created_at: DateTime::<Utc>::from(m.created_at),
        updated_at: m.updated_at.map(DateTime::<Utc>::from),
    }
}

#[cfg(test)]
mod tests {
    use super::to_domain;
    use crate::infrastructure::database::entity::user;

    #[test]
    fn maps_oidc_phone_and_address_claim_fields() {
        let now = chrono::Utc::now().into();
        let model = user::Model {
            id: 1,
            oid: uuid::Uuid::nil(),
            email: "user@example.com".to_string(),
            email_normalized: "user@example.com".to_string(),
            name: "User".to_string(),
            name_normalized: "user".to_string(),
            given_name: None,
            family_name: None,
            middle_name: None,
            nickname: None,
            profile: None,
            picture: None,
            website: None,
            gender: None,
            birthdate: None,
            zone_info: None,
            locale: None,
            email_verified: true,
            phone_number: Some("+12025550123".to_string()),
            phone_number_verified: Some(true),
            address_formatted: Some("1 Main St\nExample City".to_string()),
            address_street_address: Some("1 Main St".to_string()),
            address_locality: Some("Example City".to_string()),
            address_region: Some("CA".to_string()),
            address_postal_code: Some("94000".to_string()),
            address_country: Some("US".to_string()),
            failed_attempts: 0,
            enabled: true,
            locked: false,
            locked_until: None,
            created_at: now,
            updated_at: None,
        };

        let user = to_domain(model);

        assert_eq!(user.phone_number.as_deref(), Some("+12025550123"));
        assert_eq!(user.phone_number_verified, Some(true));
        assert_eq!(
            user.address_formatted.as_deref(),
            Some("1 Main St\nExample City")
        );
        assert_eq!(user.address_street_address.as_deref(), Some("1 Main St"));
        assert_eq!(user.address_locality.as_deref(), Some("Example City"));
        assert_eq!(user.address_region.as_deref(), Some("CA"));
        assert_eq!(user.address_postal_code.as_deref(), Some("94000"));
        assert_eq!(user.address_country.as_deref(), Some("US"));
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
        let normalized = crate::domain::user::normalization::normalize_identifier(identifier)
            .ok_or(UserRepositoryError::UserNotFound)?;
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
