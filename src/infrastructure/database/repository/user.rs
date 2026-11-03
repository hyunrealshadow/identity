use async_trait::async_trait;
use chrono::{DateTime, FixedOffset, Utc};
use identity_domain::user::{
    MfaMethod, User, UserOid, UserTheme,
    normalization::normalize_identifier,
    repository::{UserIdentifierUpdate, UserProfilePatch, UserRepository, UserRepositoryError},
};
use sea_orm::{
    ActiveModelTrait, ColumnTrait, Condition, ConnectionTrait, DatabaseConnection, EntityTrait,
    ExprTrait, QueryFilter, QuerySelect, Set, sea_query::Expr,
};
use serde_json::{Value, json};
use uuid::Uuid;

use super::authorization_lifecycle::{renew_user_version_in_txn, sync_user_authority_in_txn};
use crate::database::{
    audit,
    entity::{
        user,
        user::{Column as UserColumn, Entity as UserEntity},
    },
};

pub(crate) fn to_domain(m: user::Model) -> Result<User, UserRepositoryError> {
    let preferred_mfa_method = m
        .preferences
        .get("preferred_mfa_method")
        .cloned()
        .map(serde_json::from_value::<MfaMethod>)
        .transpose()
        .map_err(|_| UserRepositoryError::InvalidStoredMfaPreference)?
        .unwrap_or_default();
    let theme = m
        .preferences
        .get("theme")
        .and_then(Value::as_str)
        .map(str::parse)
        .transpose()
        .map_err(|_| UserRepositoryError::InvalidStoredTheme)?;
    Ok(User {
        oid: m.oid.into(),
        version: m.version,
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
        theme,
        preferred_mfa_method,
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
        locked_until: m.locked_until.map(DateTime::<Utc>::from),
        created_at: DateTime::<Utc>::from(m.created_at),
        updated_at: m.updated_at.map(DateTime::<Utc>::from),
    })
}

pub(crate) fn update_theme_preference(preferences: &mut Value, theme: Option<UserTheme>) {
    if !preferences.is_object() {
        *preferences = json!({});
    }
    let object = preferences
        .as_object_mut()
        .expect("normalized preference value must be an object");
    match theme {
        Some(theme) => {
            object.insert("theme".to_owned(), Value::String(theme.to_string()));
        }
        None => {
            object.remove("theme");
        }
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

    #[tracing::instrument(skip_all, name = "db.query", fields(db.system = "postgresql", db.operation = "update_profile"))]
    pub async fn update_profile(
        &self,
        oid: UserOid,
        mut patch: UserProfilePatch,
    ) -> Result<Option<User>, UserRepositoryError> {
        // Serialize preference patches with profile/theme changes to preserve all JSON keys.
        let txn = audit::begin(&self.db, "account.update_profile")
            .await
            .map_err(|error| UserRepositoryError::QueryFailed(Box::new(error)))?;
        let Some(model) = UserEntity::find()
            .filter(UserColumn::Oid.eq(Uuid::from(oid)))
            .lock_exclusive()
            .one(&txn)
            .await
            .map_err(|error| UserRepositoryError::QueryFailed(Box::new(error)))?
        else {
            return Ok(None);
        };
        let mut preferences = model.preferences.clone();
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
        let preferences_changed = patch.theme.is_some() || patch.preferred_mfa_method.is_some();
        if let Some(theme) = patch.theme.take() {
            update_theme_preference(&mut preferences, theme);
        }
        if let Some(method) = patch.preferred_mfa_method {
            if !preferences.is_object() {
                preferences = json!({});
            }
            preferences["preferred_mfa_method"] = json!(method);
        }
        if preferences_changed {
            active.preferences = Set(preferences);
        }
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
        let mut model = active
            .update(&txn)
            .await
            .map_err(|error| UserRepositoryError::QueryFailed(Box::new(error)))?;
        model.version = renew_user_version_in_txn(&txn, model.id)
            .await
            .map_err(|error| UserRepositoryError::QueryFailed(Box::new(error)))?
            .as_uuid();
        audit::record(&txn, "account.update_profile", "user", oid.0)
            .await
            .map_err(|error| UserRepositoryError::QueryFailed(Box::new(error)))?;
        let user = to_domain(model)?;
        txn.commit()
            .await
            .map_err(|error| UserRepositoryError::QueryFailed(Box::new(error)))?;
        Ok(Some(user))
    }

    #[tracing::instrument(skip_all, name = "db.query", fields(db.system = "postgresql", db.operation = "update_identifier"))]
    pub async fn update_identifier(
        &self,
        oid: UserOid,
        update: UserIdentifierUpdate,
    ) -> Result<Option<User>, UserRepositoryError> {
        let txn = audit::begin(&self.db, "account.update_identifier")
            .await
            .map_err(|error| UserRepositoryError::QueryFailed(Box::new(error)))?;
        let Some(model) = UserEntity::find()
            .filter(UserColumn::Oid.eq(Uuid::from(oid)))
            .lock_exclusive()
            .one(&txn)
            .await
            .map_err(|error| UserRepositoryError::QueryFailed(Box::new(error)))?
        else {
            return Ok(None);
        };

        let mut active: user::ActiveModel = model.clone().into();
        match &update {
            UserIdentifierUpdate::Username { value, normalized } => {
                if normalized != &model.name_normalized
                    && Self::identifier_exists(
                        &txn,
                        UserColumn::NameNormalized,
                        normalized,
                        model.id,
                    )
                    .await?
                {
                    return Err(UserRepositoryError::UsernameExists);
                }
                active.name = Set(value.clone());
                active.name_normalized = Set(normalized.clone());
            }
            UserIdentifierUpdate::Email { value, normalized } => {
                if normalized != &model.email_normalized
                    && Self::identifier_exists(
                        &txn,
                        UserColumn::EmailNormalized,
                        normalized,
                        model.id,
                    )
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
        match active.update(&txn).await {
            Ok(mut model) => {
                model.version = renew_user_version_in_txn(&txn, model.id)
                    .await
                    .map_err(|error| UserRepositoryError::QueryFailed(Box::new(error)))?
                    .as_uuid();
                audit::record(&txn, "account.update_identifier", "user", oid.0)
                    .await
                    .map_err(|error| UserRepositoryError::QueryFailed(Box::new(error)))?;
                let user = to_domain(model)?;
                txn.commit()
                    .await
                    .map_err(|error| UserRepositoryError::QueryFailed(Box::new(error)))?;
                Ok(Some(user))
            }
            Err(error) => {
                txn.rollback()
                    .await
                    .map_err(|error| UserRepositoryError::QueryFailed(Box::new(error)))?;
                match &update {
                    UserIdentifierUpdate::Username { normalized, .. }
                        if Self::identifier_exists(
                            &self.db,
                            UserColumn::NameNormalized,
                            normalized,
                            model.id,
                        )
                        .await? =>
                    {
                        return Err(UserRepositoryError::UsernameExists);
                    }
                    UserIdentifierUpdate::Email { normalized, .. }
                        if Self::identifier_exists(
                            &self.db,
                            UserColumn::EmailNormalized,
                            normalized,
                            model.id,
                        )
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

    #[tracing::instrument(skip_all, name = "db.query", fields(db.system = "postgresql", db.operation = "identifier_exists"))]
    async fn identifier_exists(
        connection: &impl ConnectionTrait,
        column: user::Column,
        normalized: &str,
        except_id: i64,
    ) -> Result<bool, UserRepositoryError> {
        UserEntity::find()
            .filter(column.eq(normalized))
            .filter(UserColumn::Id.ne(except_id))
            .one(connection)
            .await
            .map(|user| user.is_some())
            .map_err(|error| UserRepositoryError::QueryFailed(Box::new(error)))
    }
}

#[async_trait]
impl UserRepository for UserRepositoryImpl {
    #[tracing::instrument(skip_all, name = "db.query", fields(db.system = "postgresql", db.operation = "find_by_identifier"))]
    async fn find_by_identifier(&self, identifier: &str) -> Result<User, UserRepositoryError> {
        let normalized =
            normalize_identifier(identifier).ok_or(UserRepositoryError::UserNotFound)?;
        let model = UserEntity::find()
            .filter(
                Condition::any()
                    .add(UserColumn::EmailNormalized.eq(&normalized))
                    .add(UserColumn::NameNormalized.eq(&normalized)),
            )
            .one(&self.db)
            .await
            .map_err(|e| UserRepositoryError::QueryFailed(Box::new(e)))?;
        model
            .map(to_domain)
            .transpose()?
            .ok_or(UserRepositoryError::UserNotFound)
    }

    #[tracing::instrument(skip_all, name = "db.query", fields(db.system = "postgresql", db.operation = "find_by_oid"))]
    async fn find_by_oid(&self, oid: UserOid) -> Result<Option<User>, UserRepositoryError> {
        let model = UserEntity::find()
            .filter(UserColumn::Oid.eq(Uuid::from(oid)))
            .one(&self.db)
            .await
            .map_err(|e| UserRepositoryError::QueryFailed(Box::new(e)))?;
        model.map(to_domain).transpose()
    }

    #[tracing::instrument(skip_all, name = "db.query", fields(db.system = "postgresql", db.operation = "increment_failed_attempts"))]
    async fn increment_failed_attempts(
        &self,
        user_oid: UserOid,
        lock_threshold: i32,
        lock_until: DateTime<Utc>,
    ) -> Result<i32, UserRepositoryError> {
        let oid = Uuid::from(user_oid);
        let now = Utc::now().fixed_offset();
        let transaction = audit::begin(&self.db, "account.increment_failed_attempts")
            .await
            .map_err(|error| UserRepositoryError::UpdateFailedAttempts(Box::new(error)))?;
        let updated = UserEntity::update_many()
            .col_expr(
                UserColumn::FailedAttempts,
                Expr::col(UserColumn::FailedAttempts).add(1),
            )
            .col_expr(UserColumn::UpdatedAt, Expr::value(Some(now)))
            .filter(UserColumn::Oid.eq(oid))
            .exec_with_returning(&transaction)
            .await
            .map_err(|error| UserRepositoryError::UpdateFailedAttempts(Box::new(error)))?
            .into_iter()
            .next()
            .ok_or(UserRepositoryError::UserNotFound)?;
        let attempts = updated.failed_attempts;
        let was_locked = updated.locked;

        if attempts >= lock_threshold {
            let locked = UserEntity::update_many()
                .col_expr(UserColumn::Locked, Expr::value(true))
                .col_expr(
                    UserColumn::LockedUntil,
                    Expr::value(Some(lock_until.fixed_offset())),
                )
                .col_expr(UserColumn::UpdatedAt, Expr::value(Some(now)))
                .filter(UserColumn::Oid.eq(oid))
                .exec_with_returning(&transaction)
                .await
                .map_err(|error| UserRepositoryError::UpdateFailedAttempts(Box::new(error)))?
                .into_iter()
                .next()
                .ok_or(UserRepositoryError::UserNotFound)?;
            // Account authority changes invalidate old management authorization
            // snapshots and bindings. A temporary finite lockout still counts as
            // recoverable.
            if !was_locked && locked.locked {
                sync_user_authority_in_txn(&transaction, locked.id)
                    .await
                    .map_err(|error| UserRepositoryError::UpdateFailedAttempts(Box::new(error)))?;
            } else {
                renew_user_version_in_txn(&transaction, updated.id)
                    .await
                    .map_err(|error| UserRepositoryError::UpdateFailedAttempts(Box::new(error)))?;
            }
        } else {
            renew_user_version_in_txn(&transaction, updated.id)
                .await
                .map_err(|error| UserRepositoryError::UpdateFailedAttempts(Box::new(error)))?;
        }
        audit::record(
            &transaction,
            "account.increment_failed_attempts",
            "user",
            oid,
        )
        .await
        .map_err(|error| UserRepositoryError::UpdateFailedAttempts(Box::new(error)))?;
        transaction
            .commit()
            .await
            .map_err(|error| UserRepositoryError::UpdateFailedAttempts(Box::new(error)))?;
        Ok(attempts)
    }

    #[tracing::instrument(skip_all, name = "db.query", fields(db.system = "postgresql", db.operation = "reset_failed_attempts"))]
    async fn reset_failed_attempts(&self, user_oid: UserOid) -> Result<(), UserRepositoryError> {
        let oid = Uuid::from(user_oid);
        let now = Utc::now().fixed_offset();
        let transaction = audit::begin(&self.db, "account.reset_failed_attempts")
            .await
            .map_err(|error| UserRepositoryError::ResetFailedAttempts(Box::new(error)))?;
        let current = UserEntity::find()
            .select_only()
            .columns([UserColumn::Id, UserColumn::Locked])
            .filter(UserColumn::Oid.eq(oid))
            .lock_exclusive()
            .into_tuple::<(i64, bool)>()
            .one(&transaction)
            .await
            .map_err(|error| UserRepositoryError::ResetFailedAttempts(Box::new(error)))?;
        let Some((user_id, was_locked)) = current else {
            transaction
                .commit()
                .await
                .map_err(|error| UserRepositoryError::ResetFailedAttempts(Box::new(error)))?;
            return Ok(());
        };
        UserEntity::update_many()
            .col_expr(UserColumn::FailedAttempts, Expr::value(0i32))
            .col_expr(UserColumn::Locked, Expr::value(false))
            .col_expr(
                UserColumn::LockedUntil,
                Expr::value(Option::<DateTime<FixedOffset>>::None),
            )
            .col_expr(UserColumn::UpdatedAt, Expr::value(Some(now)))
            .filter(UserColumn::Oid.eq(oid))
            .exec(&transaction)
            .await
            .map_err(|e| UserRepositoryError::ResetFailedAttempts(Box::new(e)))?;
        if was_locked {
            sync_user_authority_in_txn(&transaction, user_id)
                .await
                .map_err(|error| UserRepositoryError::ResetFailedAttempts(Box::new(error)))?;
        } else {
            renew_user_version_in_txn(&transaction, user_id)
                .await
                .map_err(|error| UserRepositoryError::ResetFailedAttempts(Box::new(error)))?;
        }
        audit::record(&transaction, "account.reset_failed_attempts", "user", oid)
            .await
            .map_err(|error| UserRepositoryError::ResetFailedAttempts(Box::new(error)))?;
        transaction
            .commit()
            .await
            .map_err(|e| UserRepositoryError::ResetFailedAttempts(Box::new(e)))?;
        Ok(())
    }

    #[tracing::instrument(skip_all, name = "db.query", fields(db.system = "postgresql", db.operation = "update_identifier"))]
    async fn update_identifier(
        &self,
        oid: UserOid,
        update: UserIdentifierUpdate,
    ) -> Result<Option<User>, UserRepositoryError> {
        UserRepositoryImpl::update_identifier(self, oid, update).await
    }

    #[tracing::instrument(skip_all, name = "db.query", fields(db.system = "postgresql", db.operation = "update_profile"))]
    async fn update_profile(
        &self,
        oid: UserOid,
        patch: UserProfilePatch,
    ) -> Result<Option<User>, UserRepositoryError> {
        UserRepositoryImpl::update_profile(self, oid, patch).await
    }
}

#[cfg(test)]
mod tests {

    use chrono::Utc;
    use identity_domain::user::{MfaMethod, UserTheme, repository::UserRepositoryError};
    use serde_json::json;
    use uuid::Uuid;

    use super::{to_domain, update_theme_preference};
    use crate::database::entity::user;

    #[test]
    fn maps_oidc_phone_and_address_claim_fields() {
        let model = user_model();

        let user = to_domain(model).unwrap();

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
        assert_eq!(user.theme.map(UserTheme::as_str), Some("dark"));
    }

    #[test]
    fn mfa_preference_defaults_and_rejects_corrupt_values() {
        let mut model = user_model();
        assert_eq!(
            to_domain(model.clone()).unwrap().preferred_mfa_method,
            MfaMethod::Passkey
        );
        model.preferences["preferred_mfa_method"] = json!("otp");
        assert_eq!(
            to_domain(model.clone()).unwrap().preferred_mfa_method,
            MfaMethod::Otp
        );
        model.preferences["preferred_mfa_method"] = json!("unsupported");
        assert!(matches!(
            to_domain(model),
            Err(UserRepositoryError::InvalidStoredMfaPreference)
        ));
    }

    #[test]
    fn updating_theme_preserves_other_json_preferences() {
        let mut preferences = json!({
            "theme": "light",
            "compact_navigation": true,
            "preferred_mfa_method": "otp",
        });

        update_theme_preference(&mut preferences, Some(UserTheme::Dark));

        assert_eq!(preferences["theme"], "dark");
        assert_eq!(preferences["compact_navigation"], true);
        assert_eq!(preferences["preferred_mfa_method"], "otp");

        update_theme_preference(&mut preferences, None);

        assert!(preferences.get("theme").is_none());
        assert_eq!(preferences["compact_navigation"], true);
    }

    fn user_model() -> user::Model {
        let now = Utc::now().into();
        user::Model {
            id: 1,
            oid: Uuid::nil(),
            version: Uuid::new_v4(),
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
            preferences: json!({ "theme": "dark" }),
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
