use async_trait::async_trait;
use chrono::{DateTime, Utc};
use sea_orm::{
    ActiveModelTrait, ColumnTrait, DatabaseConnection, EntityTrait, ExprTrait, QueryFilter, Set,
    TransactionTrait, sea_query::Expr,
};

use crate::database::entity::{user, user::Entity as UserEntity};
use identity_domain::user::{
    User, UserOid,
    repository::{UserRepository, UserRepositoryError},
};

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
        locked_until: m.locked_until.map(chrono::DateTime::<Utc>::from),
        created_at: DateTime::<Utc>::from(m.created_at),
        updated_at: m.updated_at.map(DateTime::<Utc>::from),
    }
}

pub struct UserRepositoryImpl {
    db: DatabaseConnection,
}

macro_rules! apply_patch {
    ($active:ident, $patch:ident, $($field:ident),+ $(,)?) => {
        $(
            if let Some(value) = $patch.$field.take() {
                $active.$field = Set(value);
            }
        )+
    };
}

impl UserRepositoryImpl {
    pub fn new(db: DatabaseConnection) -> Self {
        Self { db }
    }

    pub async fn update_profile(
        &self,
        oid: UserOid,
        mut patch: UserProfilePatch,
    ) -> Result<Option<User>, UserRepositoryError> {
        let Some(model) = UserEntity::find()
            .filter(user::Column::Oid.eq(uuid::Uuid::from(oid)))
            .one(&self.db)
            .await
            .map_err(|error| UserRepositoryError::QueryFailed(Box::new(error)))?
        else {
            return Ok(None);
        };
        let mut active: user::ActiveModel = model.into();
        apply_patch!(
            active,
            patch,
            given_name,
            family_name,
            middle_name,
            nickname
        );
        apply_patch!(active, patch, profile, picture, website, gender);
        apply_patch!(active, patch, birthdate, zone_info, locale);
        apply_patch!(
            active,
            patch,
            address_formatted,
            address_street_address,
            address_locality,
            address_region,
            address_postal_code,
            address_country
        );
        active.updated_at = Set(Some(Utc::now().into()));
        active
            .update(&self.db)
            .await
            .map(to_domain)
            .map(Some)
            .map_err(|error| UserRepositoryError::QueryFailed(Box::new(error)))
    }

    pub async fn update_identifier(
        &self,
        oid: UserOid,
        update: UserIdentifierUpdate,
    ) -> Result<Option<User>, UserRepositoryError> {
        let Some(model) = UserEntity::find()
            .filter(user::Column::Oid.eq(uuid::Uuid::from(oid)))
            .one(&self.db)
            .await
            .map_err(|error| UserRepositoryError::QueryFailed(Box::new(error)))?
        else {
            return Ok(None);
        };

        let mut active: user::ActiveModel = model.clone().into();
        match &update {
            UserIdentifierUpdate::Username { value, normalized } => {
                if normalized != &model.name_normalized
                    && self
                        .identifier_exists(user::Column::NameNormalized, normalized, model.id)
                        .await?
                {
                    return Err(UserRepositoryError::UsernameExists);
                }
                active.name = Set(value.clone());
                active.name_normalized = Set(normalized.clone());
            }
            UserIdentifierUpdate::Email { value, normalized } => {
                if normalized != &model.email_normalized
                    && self
                        .identifier_exists(user::Column::EmailNormalized, normalized, model.id)
                        .await?
                {
                    return Err(UserRepositoryError::EmailExists);
                }
                let changed = normalized != &model.email_normalized;
                active.email = Set(value.clone());
                active.email_normalized = Set(normalized.clone());
                if changed {
                    active.email_verified = Set(false);
                }
            }
        }
        active.updated_at = Set(Some(Utc::now().into()));
        match active.update(&self.db).await {
            Ok(model) => Ok(Some(to_domain(model))),
            Err(error) => {
                match &update {
                    UserIdentifierUpdate::Username { normalized, .. }
                        if self
                            .identifier_exists(user::Column::NameNormalized, normalized, model.id)
                            .await? =>
                    {
                        return Err(UserRepositoryError::UsernameExists);
                    }
                    UserIdentifierUpdate::Email { normalized, .. }
                        if self
                            .identifier_exists(user::Column::EmailNormalized, normalized, model.id)
                            .await? =>
                    {
                        return Err(UserRepositoryError::EmailExists);
                    }
                    _ => {}
                }
                Err(UserRepositoryError::QueryFailed(Box::new(error)))
            }
        }
    }

    async fn identifier_exists(
        &self,
        column: user::Column,
        normalized: &str,
        except_id: i64,
    ) -> Result<bool, UserRepositoryError> {
        UserEntity::find()
            .filter(column.eq(normalized))
            .filter(user::Column::Id.ne(except_id))
            .one(&self.db)
            .await
            .map(|user| user.is_some())
            .map_err(|error| UserRepositoryError::QueryFailed(Box::new(error)))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UserIdentifierUpdate {
    Username { value: String, normalized: String },
    Email { value: String, normalized: String },
}

#[derive(Debug, Default)]
pub struct UserProfilePatch {
    pub given_name: Option<Option<String>>,
    pub family_name: Option<Option<String>>,
    pub middle_name: Option<Option<String>>,
    pub nickname: Option<Option<String>>,
    pub profile: Option<Option<String>>,
    pub picture: Option<Option<String>>,
    pub website: Option<Option<String>>,
    pub gender: Option<Option<String>>,
    pub birthdate: Option<Option<String>>,
    pub zone_info: Option<Option<String>>,
    pub locale: Option<Option<String>>,
    pub address_formatted: Option<Option<String>>,
    pub address_street_address: Option<Option<String>>,
    pub address_locality: Option<Option<String>>,
    pub address_region: Option<Option<String>>,
    pub address_postal_code: Option<Option<String>>,
    pub address_country: Option<Option<String>>,
}

#[async_trait]
impl UserRepository for UserRepositoryImpl {
    async fn find_by_identifier(&self, identifier: &str) -> Result<User, UserRepositoryError> {
        use sea_orm::Condition;
        let normalized = identity_domain::user::normalization::normalize_identifier(identifier)
            .ok_or(UserRepositoryError::UserNotFound)?;
        let model = UserEntity::find()
            .filter(
                Condition::any()
                    .add(user::Column::EmailNormalized.eq(&normalized))
                    .add(user::Column::NameNormalized.eq(&normalized)),
            )
            .one(&self.db)
            .await
            .map_err(|e| UserRepositoryError::QueryFailed(Box::new(e)))?;
        model
            .map(to_domain)
            .ok_or(UserRepositoryError::UserNotFound)
    }

    async fn find_by_oid(&self, oid: UserOid) -> Result<Option<User>, UserRepositoryError> {
        let model = UserEntity::find()
            .filter(user::Column::Oid.eq(uuid::Uuid::from(oid)))
            .one(&self.db)
            .await
            .map_err(|e| UserRepositoryError::QueryFailed(Box::new(e)))?;
        Ok(model.map(to_domain))
    }

    async fn increment_failed_attempts(
        &self,
        user_oid: UserOid,
        lock_threshold: i32,
        lock_until: DateTime<Utc>,
    ) -> Result<i32, UserRepositoryError> {
        let oid = uuid::Uuid::from(user_oid);
        let now = Utc::now().naive_utc();
        let transaction = self
            .db
            .begin()
            .await
            .map_err(|error| UserRepositoryError::UpdateFailedAttempts(Box::new(error)))?;
        let updated = UserEntity::update_many()
            .col_expr(
                user::Column::FailedAttempts,
                Expr::col(user::Column::FailedAttempts).add(1),
            )
            .col_expr(
                user::Column::UpdatedAt,
                Expr::value(Option::<chrono::NaiveDateTime>::Some(now)),
            )
            .filter(user::Column::Oid.eq(oid))
            .exec_with_returning(&transaction)
            .await
            .map_err(|error| UserRepositoryError::UpdateFailedAttempts(Box::new(error)))?
            .into_iter()
            .next()
            .ok_or(UserRepositoryError::UserNotFound)?;
        let attempts = updated.failed_attempts;

        if attempts >= lock_threshold {
            UserEntity::update_many()
                .col_expr(user::Column::Locked, Expr::value(true))
                .col_expr(
                    user::Column::LockedUntil,
                    Expr::value(Option::<chrono::NaiveDateTime>::Some(
                        lock_until.naive_utc(),
                    )),
                )
                .filter(user::Column::Oid.eq(oid))
                .exec(&transaction)
                .await
                .map_err(|error| UserRepositoryError::UpdateFailedAttempts(Box::new(error)))?;
        }

        transaction
            .commit()
            .await
            .map_err(|error| UserRepositoryError::UpdateFailedAttempts(Box::new(error)))?;
        Ok(attempts)
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
            .map_err(|e| UserRepositoryError::ResetFailedAttempts(Box::new(e)))?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use sea_orm::{DatabaseBackend, MockDatabase};

    use super::{UserIdentifierUpdate, UserRepositoryImpl, to_domain};
    use crate::database::entity::user;

    #[test]
    fn maps_oidc_phone_and_address_claim_fields() {
        let model = user_model();

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

    #[tokio::test]
    async fn identifier_update_marks_a_changed_email_unverified() {
        let current = user_model();
        let current_name = current.name.clone();
        let mut updated = current.clone();
        updated.email = "ada@new.example".to_owned();
        updated.email_normalized = "ada@new.example".to_owned();
        updated.email_verified = false;
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_results([vec![current], Vec::<user::Model>::new(), vec![updated]])
            .into_connection();
        let repo = UserRepositoryImpl::new(db);

        let user = repo
            .update_identifier(
                uuid::Uuid::nil().into(),
                UserIdentifierUpdate::Email {
                    value: "ada@new.example".to_owned(),
                    normalized: "ada@new.example".to_owned(),
                },
            )
            .await
            .unwrap()
            .unwrap();

        assert_eq!(user.name, current_name);
        assert_eq!(user.email, "ada@new.example");
        assert!(!user.email_verified);
    }

    fn user_model() -> user::Model {
        let now = chrono::Utc::now().into();
        user::Model {
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
        }
    }
}
