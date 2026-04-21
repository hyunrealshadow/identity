//! Conformance-environment seed.
//!
//! Creates the fixed test user and OIDC client that the OpenID Conformance
//! Test Suite expects.  This module is only called when `APP_ENV=conformance`.
//!
//! All operations are idempotent: rows are inserted only when the fixed OIDs
//! are not already present, so re-starting a container with an existing volume
//! is safe.

use async_trait::async_trait;
use chrono::Utc;
use sea_orm::{
    ActiveModelTrait, ColumnTrait, DatabaseConnection, EntityTrait, QueryFilter, Set,
    TransactionTrait,
};
use uuid::Uuid;

use crate::{
    application::error::AppError,
    application::error::codes::common::CommonErrorCode,
    infrastructure::database::entity::{
        client, client_open_id_connect, client_open_id_connect_credential, user, user_credential,
    },
};

use super::Seed;

/// Seed that creates the fixed conformance test user and OIDC client.
pub struct ConformanceSeed;

#[async_trait]
impl Seed for ConformanceSeed {
    fn name(&self) -> &'static str {
        "conformance"
    }

    async fn run(&self, db: &DatabaseConnection) -> Result<(), AppError> {
        run(db).await
    }
}

/// Fixed UUIDs so every fresh container produces the same client_id that the
/// conformance suite config references.
const USER_OID: &str = "00000000-0000-0000-0000-000000000001";
const USER_CRED_OID: &str = "00000000-0000-0000-0000-000000000002";
const CLIENT_OID: &str = "00000001-0000-0000-0000-000000000001";
const CLIENT_CRED_OID: &str = "00000001-0000-0000-0000-000000000002";

/// Public constant for the conformance client OID, used by other modules to
/// identify this special client (e.g. to skip consent automatically).
pub const CONFORMANCE_CLIENT_OID: &str = CLIENT_OID;

pub const CONFORMANCE_USERNAME: &str = "conformance-test";
pub const CONFORMANCE_EMAIL: &str = "conformance-test@example.com";
/// Plain-text password used by the auto-login endpoint.
pub const CONFORMANCE_PASSWORD: &str = "ConformanceTest1!";

pub const CONFORMANCE_CLIENT_NAME: &str = "OpenID Conformance Suite";
pub const CONFORMANCE_CLIENT_SECRET: &str = "conformance-secret";

/// Run the conformance seed.  Safe to call multiple times.
pub async fn run(db: &DatabaseConnection) -> Result<(), AppError> {
    let txn = db
        .begin()
        .await
        .map_err(|e| AppError::from_code(CommonErrorCode::InternalError).with_source(e))?;

    let user_oid: Uuid = USER_OID.parse().expect("USER_OID literal is valid");
    let user_cred_oid: Uuid = USER_CRED_OID
        .parse()
        .expect("USER_CRED_OID literal is valid");
    let client_oid: Uuid = CLIENT_OID.parse().expect("CLIENT_OID literal is valid");
    let client_cred_oid: Uuid = CLIENT_CRED_OID
        .parse()
        .expect("CLIENT_CRED_OID literal is valid");

    let now = Utc::now();

    // ── Test user ──────────────────────────────────────────────────────────

    let existing_user = user::Entity::find()
        .filter(user::Column::Oid.eq(user_oid))
        .one(&txn)
        .await
        .map_err(|e| AppError::from_code(CommonErrorCode::InternalError).with_source(e))?;

    let user_id = if let Some(u) = existing_user {
        tracing::debug!("conformance seed: user already exists, skipping");
        u.id
    } else {
        // Hash the password using the same Argon2id defaults as the rest of the app.
        let password_json = hash_conformance_password()?;

        let created_user = user::ActiveModel {
            oid: Set(user_oid),
            email: Set(CONFORMANCE_EMAIL.to_owned()),
            email_normalized: Set(CONFORMANCE_EMAIL.to_owned()),
            name: Set(CONFORMANCE_USERNAME.to_owned()),
            name_normalized: Set(CONFORMANCE_USERNAME.to_owned()),
            email_verified: Set(true),
            failed_attempts: Set(0),
            enabled: Set(true),
            locked: Set(false),
            locked_until: Set(None),
            created_at: Set(now.into()),
            updated_at: Set(Some(now.into())),
            ..Default::default()
        }
        .insert(&txn)
        .await
        .map_err(|e| AppError::from_code(CommonErrorCode::InternalError).with_source(e))?;

        let _ = user_credential::ActiveModel {
            oid: Set(user_cred_oid),
            user_id: Set(created_user.id),
            r#type: Set("password".to_owned()),
            data: Set(password_json),
            created_at: Set(now.into()),
            updated_at: Set(Some(now.into())),
            ..Default::default()
        }
        .insert(&txn)
        .await
        .map_err(|e| AppError::from_code(CommonErrorCode::InternalError).with_source(e))?;

        tracing::info!("conformance seed: created test user");
        created_user.id
    };
    let _ = user_id; // used only for logging; client rows don't need it

    // ── OIDC client ────────────────────────────────────────────────────────

    let existing_client = client::Entity::find()
        .filter(client::Column::Oid.eq(client_oid))
        .one(&txn)
        .await
        .map_err(|e| AppError::from_code(CommonErrorCode::InternalError).with_source(e))?;

    if existing_client.is_some() {
        tracing::debug!("conformance seed: OIDC client already exists, skipping");
    } else {
        let created_client = client::ActiveModel {
            oid: Set(client_oid),
            protocol: Set("openid_connect".to_owned()),
            name: Set(CONFORMANCE_CLIENT_NAME.to_owned()),
            names: Set(None),
            description: Set(None),
            created_at: Set(now.naive_utc()),
            updated_at: Set(None),
            ..Default::default()
        }
        .insert(&txn)
        .await
        .map_err(|e| AppError::from_code(CommonErrorCode::InternalError).with_source(e))?;

        let redirect_uris =
            serde_json::json!(["https://localhost.emobix.co.uk:8443/test/a/identity/callback"]);
        let grant_types = serde_json::json!(["authorization_code"]);
        let response_types = serde_json::json!(["code"]);

        let _ = client_open_id_connect::ActiveModel {
            client_id: Set(created_client.id),
            redirect_uris: Set(Some(redirect_uris)),
            grant_types: Set(Some(grant_types)),
            response_types: Set(Some(response_types)),
            token_endpoint_auth_method: Set(Some("client_secret_basic".to_owned())),
            created_at: Set(now.into()),
            updated_at: Set(None),
            ..Default::default()
        }
        .insert(&txn)
        .await
        .map_err(|e| AppError::from_code(CommonErrorCode::InternalError).with_source(e))?;

        let secret_json = serde_json::json!({ "secret": CONFORMANCE_CLIENT_SECRET });
        let expires_at = chrono::DateTime::parse_from_rfc3339("9999-12-31T23:59:59+00:00")
            .expect("non-expiring timestamp literal is valid");

        let _ = client_open_id_connect_credential::ActiveModel {
            oid: Set(client_cred_oid),
            client_id: Set(created_client.id),
            r#type: Set("client_secret".to_owned()),
            data: Set(secret_json),
            hint: Set(CONFORMANCE_CLIENT_SECRET.to_owned()),
            expires_at: Set(expires_at),
            revoked_at: Set(None),
            created_at: Set(now.into()),
            updated_at: Set(None),
            ..Default::default()
        }
        .insert(&txn)
        .await
        .map_err(|e| AppError::from_code(CommonErrorCode::InternalError).with_source(e))?;

        tracing::info!("conformance seed: created OIDC client");
    }

    txn.commit()
        .await
        .map_err(|e| AppError::from_code(CommonErrorCode::InternalError).with_source(e))?;

    Ok(())
}

/// Hash `CONFORMANCE_PASSWORD` with the same Argon2id defaults the app uses,
/// and return the serialised `Password` JSON value ready for the DB.
fn hash_conformance_password() -> Result<serde_json::Value, AppError> {
    use crate::domain::user::password::{
        Argon2Options, Argon2Password, Argon2Variant, Argon2Version, Password,
    };
    use argon2::{
        Argon2, PasswordHasher,
        password_hash::{SaltString, rand_core::OsRng},
    };

    let salt = SaltString::generate(&mut OsRng);
    let params = argon2::Params::new(4_096, 1, 1, None).map_err(|e| {
        AppError::from_code(CommonErrorCode::InternalError)
            .with_source(std::io::Error::other(e.to_string()))
    })?;
    let argon2 = Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);
    let hash = argon2
        .hash_password(CONFORMANCE_PASSWORD.as_bytes(), &salt)
        .map_err(|e| {
            AppError::from_code(CommonErrorCode::InternalError)
                .with_source(std::io::Error::other(e.to_string()))
        })?;

    // Extract just the hash bytes (not the full PHC string) to match the
    // format produced by the normal hash() function in the infrastructure layer.
    let hash_bytes = hash
        .hash
        .ok_or_else(|| {
            AppError::from_code(CommonErrorCode::InternalError)
                .with_source(std::io::Error::other("missing hash output"))
        })?
        .to_string();
    let salt_b64 = salt.as_str().to_owned();

    let password = Password::Argon2(Argon2Password {
        hash: hash_bytes,
        salt: salt_b64,
        options: Argon2Options {
            variant: Argon2Variant::Argon2id,
            version: Argon2Version::Argon2013,
            time_cost: 1,
            memory_cost: 4_096,
            parallelism: 1,
        },
    });

    serde_json::to_value(&password)
        .map_err(|e| AppError::from_code(CommonErrorCode::InternalError).with_source(e))
}
