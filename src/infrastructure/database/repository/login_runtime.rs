use async_trait::async_trait;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::{DateTime, Utc};
use rand::RngExt;
use sea_orm::{
    ActiveModelTrait, ActiveValue::Set, ColumnTrait, ConnectionTrait, DatabaseConnection,
    EntityTrait, QueryFilter, QueryOrder, TransactionTrait,
};
use uuid::Uuid;

use identity_domain::openid_connect::{
    LoginRotationPolicy, LoginRuntimeConfig, LoginRuntimeRepository, LoginRuntimeRepositoryError,
    OpenIdConnectCredentialData, OpenIdConnectCredentialType,
};

use crate::database::entity::{client, client_open_id_connect_credential};

use super::openid_connect_credential::serialize_data;

pub struct LoginRuntimeRepositoryImpl {
    db: DatabaseConnection,
}

impl LoginRuntimeRepositoryImpl {
    #[must_use]
    pub fn new(db: DatabaseConnection) -> Self {
        Self { db }
    }
}

fn query_error(
    error: impl std::error::Error + Send + Sync + 'static,
) -> LoginRuntimeRepositoryError {
    LoginRuntimeRepositoryError::QueryFailed(Box::new(error))
}

fn retirement_expiry(
    current_expires_at: DateTime<Utc>,
    now: DateTime<Utc>,
    retire_after: chrono::Duration,
) -> Option<DateTime<Utc>> {
    (current_expires_at > now).then(|| current_expires_at.min(now + retire_after))
}

async fn builtin_login_client<C: ConnectionTrait>(
    db: &C,
) -> Result<Option<client::Model>, LoginRuntimeRepositoryError> {
    client::Entity::find()
        .filter(client::Column::BuiltIn.eq(true))
        .filter(client::Column::Protocol.eq("openid_connect"))
        .order_by_asc(client::Column::CreatedAt)
        .one(db)
        .await
        .map_err(query_error)
}

async fn latest_secret<C: ConnectionTrait>(
    db: &C,
    client_id: i64,
    active_only: bool,
    now: DateTime<Utc>,
) -> Result<Option<client_open_id_connect_credential::Model>, LoginRuntimeRepositoryError> {
    let mut query = client_open_id_connect_credential::Entity::find()
        .filter(client_open_id_connect_credential::Column::ClientId.eq(client_id))
        .filter(
            client_open_id_connect_credential::Column::Type
                .eq(OpenIdConnectCredentialType::ClientSecret.to_string()),
        )
        .filter(client_open_id_connect_credential::Column::RevokedAt.is_null())
        .order_by_desc(client_open_id_connect_credential::Column::CreatedAt);
    if active_only {
        query = query.filter(client_open_id_connect_credential::Column::ExpiresAt.gt(now));
    }
    query.one(db).await.map_err(query_error)
}

#[async_trait]
impl LoginRuntimeRepository for LoginRuntimeRepositoryImpl {
    async fn login_runtime_config(
        &self,
        now: DateTime<Utc>,
    ) -> Result<Option<LoginRuntimeConfig>, LoginRuntimeRepositoryError> {
        let Some(client) = builtin_login_client(&self.db).await? else {
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
        let generation = client_open_id_connect_credential::Entity::find()
            .filter(client_open_id_connect_credential::Column::ClientId.eq(client.id))
            .filter(
                client_open_id_connect_credential::Column::Type
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

    async fn rotate_if_due(
        &self,
        now: DateTime<Utc>,
        policy: &LoginRotationPolicy,
    ) -> Result<u64, LoginRuntimeRepositoryError> {
        let txn = self.db.begin().await.map_err(query_error)?;
        txn.execute_unprepared("SELECT pg_advisory_xact_lock(684395120247316901)")
            .await
            .map_err(query_error)?;
        let Some(client) = builtin_login_client(&txn).await? else {
            txn.commit().await.map_err(query_error)?;
            return Ok(0);
        };
        let Some(current) = latest_secret(&txn, client.id, false, now).await? else {
            txn.commit().await.map_err(query_error)?;
            return Ok(0);
        };
        if current.expires_at.with_timezone(&Utc) > now + policy.rotate_before_expiry {
            txn.commit().await.map_err(query_error)?;
            return Ok(0);
        }

        let mut secret_bytes = [0_u8; 32];
        rand::rng().fill(&mut secret_bytes);
        let secret = URL_SAFE_NO_PAD.encode(secret_bytes);
        let serialized = serialize_data(OpenIdConnectCredentialData::ClientSecret { secret });
        client_open_id_connect_credential::ActiveModel {
            oid: Set(Uuid::new_v4()),
            client_id: Set(client.id),
            r#type: Set(serialized.type_),
            data: Set(serialized.data),
            hint: Set(serialized.hint),
            expires_at: Set((now + policy.credential_lifetime).into()),
            revoked_at: Set(None),
            created_at: Set(now.into()),
            updated_at: Set(Some(now.into())),
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
            client_open_id_connect_credential::Entity::update_many()
                .col_expr(
                    client_open_id_connect_credential::Column::ExpiresAt,
                    sea_orm::sea_query::Expr::value(retiring.fixed_offset()),
                )
                .col_expr(
                    client_open_id_connect_credential::Column::UpdatedAt,
                    sea_orm::sea_query::Expr::value(Some(now.fixed_offset())),
                )
                .filter(client_open_id_connect_credential::Column::Id.eq(current.id))
                .exec(&txn)
                .await
                .map_err(query_error)?;
        }
        txn.commit().await.map_err(query_error)?;
        Ok(1)
    }
}

#[cfg(test)]
mod tests {
    use chrono::{Duration, TimeZone as _, Utc};

    use super::retirement_expiry;

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
}
