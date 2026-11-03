use std::error::Error;

use async_trait::async_trait;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::{DateTime, Duration, Utc};
use identity_domain::openid_connect::{
    LoginRotationPolicy, LoginRuntimeConfig, LoginRuntimeRepository, LoginRuntimeRepositoryError,
    OpenIdConnectCredentialData, OpenIdConnectCredentialType,
};
use rand::{RngExt, rng};
use sea_orm::{
    ActiveModelTrait, ActiveValue::Set, ColumnTrait, ConnectionTrait, DatabaseConnection,
    EntityTrait, QueryFilter, QueryOrder, TransactionTrait, sea_query::Expr,
};
use uuid::Uuid;

use super::openid_connect_credential::serialize_data;
use crate::database::{
    entity::{
        client,
        client::{Column as ClientColumn, Entity as ClientEntity},
        client_openid_connect_credential,
        client_openid_connect_credential::{
            Column as ClientOpenIdConnectCredentialColumn,
            Entity as ClientOpenIdConnectCredentialEntity,
        },
    },
    query::advisory_transaction_lock,
};

pub struct LoginRuntimeRepositoryImpl {
    db: DatabaseConnection,
}

impl LoginRuntimeRepositoryImpl {
    #[must_use]
    pub fn new(db: DatabaseConnection) -> Self {
        Self { db }
    }
}

fn query_error(error: impl Error + Send + Sync + 'static) -> LoginRuntimeRepositoryError {
    LoginRuntimeRepositoryError::QueryFailed(Box::new(error))
}

fn retirement_expiry(
    current_expires_at: DateTime<Utc>,
    now: DateTime<Utc>,
    retire_after: Duration,
) -> Option<DateTime<Utc>> {
    (current_expires_at > now).then(|| current_expires_at.min(now + retire_after))
}

fn secret_is_due(
    created_at: DateTime<Utc>,
    expires_at: DateTime<Utc>,
    now: DateTime<Utc>,
    policy: &LoginRotationPolicy,
) -> bool {
    created_at <= now - Duration::days(60) || expires_at <= now + policy.rotate_before_expiry
}

async fn builtin_login_client<C: ConnectionTrait>(
    db: &C,
    client_oid: Uuid,
) -> Result<Option<client::Model>, LoginRuntimeRepositoryError> {
    ClientEntity::find()
        .filter(ClientColumn::Oid.eq(client_oid))
        .filter(ClientColumn::BuiltIn.eq(true))
        .filter(ClientColumn::Protocol.eq("openid_connect"))
        .one(db)
        .await
        .map_err(query_error)
}

async fn latest_secret<C: ConnectionTrait>(
    db: &C,
    client_id: i64,
    active_only: bool,
    now: DateTime<Utc>,
) -> Result<Option<client_openid_connect_credential::Model>, LoginRuntimeRepositoryError> {
    let mut query = ClientOpenIdConnectCredentialEntity::find()
        .filter(ClientOpenIdConnectCredentialColumn::ClientId.eq(client_id))
        .filter(
            ClientOpenIdConnectCredentialColumn::Type
                .eq(OpenIdConnectCredentialType::ClientSecret.to_string()),
        )
        .filter(ClientOpenIdConnectCredentialColumn::RevokedAt.is_null())
        .order_by_desc(ClientOpenIdConnectCredentialColumn::CreatedAt)
        .order_by_desc(ClientOpenIdConnectCredentialColumn::Id);
    if active_only {
        query = query.filter(ClientOpenIdConnectCredentialColumn::ExpiresAt.gt(now));
    }
    query.one(db).await.map_err(query_error)
}

#[async_trait]
impl LoginRuntimeRepository for LoginRuntimeRepositoryImpl {
    #[tracing::instrument(skip_all, name = "db.query", fields(db.system = "postgresql", db.operation = "login_runtime_config"))]
    async fn login_runtime_config(
        &self,
        client_oid: Uuid,
        now: DateTime<Utc>,
    ) -> Result<Option<LoginRuntimeConfig>, LoginRuntimeRepositoryError> {
        let Some(client) = builtin_login_client(&self.db, client_oid).await? else {
            return Ok(None);
        };
        let Some(credential) = latest_secret(&self.db, client.id, true, now).await? else {
            return Ok(None);
        };
        let Some(secret) = credential
            .data
            .get("secret")
            .and_then(|value| value.as_str())
        else {
            return Ok(None);
        };
        let generation = ClientOpenIdConnectCredentialEntity::find()
            .filter(ClientOpenIdConnectCredentialColumn::ClientId.eq(client.id))
            .filter(
                ClientOpenIdConnectCredentialColumn::Type
                    .eq(OpenIdConnectCredentialType::ClientSecret.to_string()),
            )
            .all(&self.db)
            .await
            .map_err(query_error)?
            .len() as i64;
        Ok(Some(LoginRuntimeConfig {
            client_oid: client.oid,
            client_secret: secret.to_owned(),
            generation,
            secret_expires_at: credential.expires_at.with_timezone(&Utc),
        }))
    }

    #[tracing::instrument(skip_all, name = "db.query", fields(db.system = "postgresql", db.operation = "rotate_builtin_if_due"))]
    async fn rotate_builtin_if_due(
        &self,
        now: DateTime<Utc>,
        policy: &LoginRotationPolicy,
    ) -> Result<u64, LoginRuntimeRepositoryError> {
        let txn = self.db.begin().await.map_err(query_error)?;
        txn.execute(&advisory_transaction_lock(684395120247316901_i64))
            .await
            .map_err(query_error)?;
        let clients = ClientEntity::find()
            .filter(ClientColumn::BuiltIn.eq(true))
            .all(&txn)
            .await
            .map_err(query_error)?;
        let mut rotated = 0;
        for client in clients {
            let Some(current) = latest_secret(&txn, client.id, false, now).await? else {
                continue;
            };
            if !secret_is_due(
                current.created_at.with_timezone(&Utc),
                current.expires_at.with_timezone(&Utc),
                now,
                policy,
            ) {
                continue;
            }

            let mut secret_bytes = [0_u8; 32];
            rng().fill(&mut secret_bytes);
            let secret = URL_SAFE_NO_PAD.encode(secret_bytes);
            let serialized = serialize_data(OpenIdConnectCredentialData::ClientSecret { secret });
            client_openid_connect_credential::ActiveModel {
                oid: Set(Uuid::new_v4()),
                client_id: Set(client.id),
                r#type: Set(serialized.type_),
                data: Set(serialized.data),
                hint: Set(serialized.hint),
                expires_at: Set((now + policy.credential_lifetime).into()),
                revoked_at: Set(None),
                created_at: Set(now.into()),
                updated_at: Set(None),
                ..Default::default()
            }
            .insert(&txn)
            .await
            .map_err(query_error)?;

            if let Some(retiring) = retirement_expiry(
                current.expires_at.with_timezone(&Utc),
                now,
                policy.retire_after,
            ) {
                ClientOpenIdConnectCredentialEntity::update_many()
                    .col_expr(
                        ClientOpenIdConnectCredentialColumn::ExpiresAt,
                        Expr::value(retiring.fixed_offset()),
                    )
                    .col_expr(
                        ClientOpenIdConnectCredentialColumn::UpdatedAt,
                        Expr::value(Some(now.fixed_offset())),
                    )
                    .filter(ClientOpenIdConnectCredentialColumn::Id.eq(current.id))
                    .exec(&txn)
                    .await
                    .map_err(query_error)?;
            }
            rotated += 1;
        }
        txn.commit().await.map_err(query_error)?;
        Ok(rotated)
    }
}

#[cfg(test)]
mod tests {
    use chrono::{Duration, TimeZone as _, Utc};
    use identity_domain::openid_connect::LoginRotationPolicy;

    use super::{retirement_expiry, secret_is_due};

    #[test]
    fn retirement_never_extends_or_resurrects_a_credential() {
        let now = Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap();

        assert_eq!(
            retirement_expiry(now - Duration::seconds(1), now, Duration::hours(24)),
            None
        );
        assert_eq!(
            retirement_expiry(now + Duration::hours(1), now, Duration::hours(24)),
            Some(now + Duration::hours(1))
        );
        assert_eq!(
            retirement_expiry(now + Duration::days(30), now, Duration::hours(24)),
            Some(now + Duration::hours(24))
        );
    }

    #[test]
    fn builtin_secret_rotates_at_day_sixty_even_if_legacy_expiry_is_later() {
        let now = Utc.with_ymd_and_hms(2026, 9, 28, 0, 0, 0).unwrap();
        let policy = LoginRotationPolicy {
            credential_lifetime: Duration::days(90),
            rotate_before_expiry: Duration::days(30),
            retire_after: Duration::days(1),
        };
        let far_expiry = now + Duration::days(120);
        assert!(!secret_is_due(
            now - Duration::days(59),
            far_expiry,
            now,
            &policy
        ));
        assert!(secret_is_due(
            now - Duration::days(60),
            far_expiry,
            now,
            &policy
        ));
    }
}
