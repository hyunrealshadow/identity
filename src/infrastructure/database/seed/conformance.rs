//! Conformance-environment seed.
//!
//! Creates the fixed test user and OIDC clients that the OpenID Conformance
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
        client, client_open_id_connect, client_open_id_connect_credential, client_platform,
        client_scope, scope, setting, user, user_credential,
    },
};
use identity_domain::setting::{DynamicClientRegistrationSetting, SettingDefinition};

use super::Seed;

/// Seed that creates the fixed conformance test user and OIDC clients.
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
const BASIC_CLIENT_OID: &str = "00000001-0000-0000-0000-000000000001";
const BASIC_CLIENT_CRED_OID: &str = "00000001-0000-0000-0000-000000000002";
const BASIC_CLIENT_POST_OID: &str = "00000002-0000-0000-0000-000000000001";
const BASIC_CLIENT_POST_CRED_OID: &str = "00000002-0000-0000-0000-000000000002";
const IMPLICIT_CLIENT_OID: &str = "00000003-0000-0000-0000-000000000001";
const IMPLICIT_CLIENT_CRED_OID: &str = "00000003-0000-0000-0000-000000000002";
const IMPLICIT_CLIENT_POST_OID: &str = "00000004-0000-0000-0000-000000000001";
const IMPLICIT_CLIENT_POST_CRED_OID: &str = "00000004-0000-0000-0000-000000000002";
const HYBRID_CLIENT_OID: &str = "00000005-0000-0000-0000-000000000001";
const HYBRID_CLIENT_CRED_OID: &str = "00000005-0000-0000-0000-000000000002";
const HYBRID_CLIENT_POST_OID: &str = "00000006-0000-0000-0000-000000000001";
const HYBRID_CLIENT_POST_CRED_OID: &str = "00000006-0000-0000-0000-000000000002";

/// Legacy public constant for the default Basic conformance client OID.
pub const CONFORMANCE_CLIENT_OID: &str = BASIC_CLIENT_OID;

pub const CONFORMANCE_USERNAME: &str = "conformance-test";
pub const CONFORMANCE_EMAIL: &str = "conformance-test@example.com";
/// Plain-text password used by the auto-login endpoint.
pub const CONFORMANCE_PASSWORD: &str = "ConformanceTest1!";

pub const CONFORMANCE_BASIC_CLIENT_NAME: &str = "OpenID Conformance Suite (Basic)";
pub const CONFORMANCE_BASIC_CLIENT_SECRET: &str = "conformance-basic-secret-at-least-32-bytes";
pub const CONFORMANCE_BASIC_CLIENT_POST_SECRET: &str = "conformance-secret-2";
pub const CONFORMANCE_IMPLICIT_CLIENT_NAME: &str = "OpenID Conformance Suite (Implicit)";
pub const CONFORMANCE_IMPLICIT_CLIENT_SECRET: &str = "conformance-implicit-secret";
pub const CONFORMANCE_IMPLICIT_CLIENT_POST_SECRET: &str = "conformance-implicit-secret-2";
pub const CONFORMANCE_HYBRID_CLIENT_NAME: &str = "OpenID Conformance Suite (Hybrid)";
pub const CONFORMANCE_HYBRID_CLIENT_SECRET: &str = "conformance-hybrid-secret";
pub const CONFORMANCE_HYBRID_CLIENT_POST_SECRET: &str = "conformance-hybrid-secret-2";

struct ConformanceClientSpec {
    oid: &'static str,
    credential_oid: &'static str,
    name: &'static str,
    secret: &'static str,
    token_endpoint_auth_method: &'static str,
    grant_types: &'static [&'static str],
    response_types: &'static [&'static str],
}

struct ConformanceOidcMetadataValues {
    grant_types: serde_json::Value,
    response_types: serde_json::Value,
    token_endpoint_auth_method: Option<String>,
    post_logout_redirect_uris: Option<serde_json::Value>,
    frontchannel_logout_uri: Option<String>,
    frontchannel_logout_session_required: Option<bool>,
    backchannel_logout_uri: Option<String>,
    backchannel_logout_session_required: Option<bool>,
    settings: serde_json::Value,
}

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

    let now = Utc::now();

    ensure_dynamic_registration_enabled(&txn, now).await?;

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
            given_name: Set(Some("Conformance".to_owned())),
            family_name: Set(Some("Test".to_owned())),
            middle_name: Set(Some("Conformance Test".to_owned())),
            nickname: Set(Some(CONFORMANCE_USERNAME.to_owned())),
            profile: Set(Some(format!("users/{USER_OID}"))),
            picture: Set(Some(format!("users/{USER_OID}/picture"))),
            website: Set(Some(format!("users/{USER_OID}"))),
            gender: Set(Some("unspecified".to_owned())),
            birthdate: Set(Some("1970-01-01".to_owned())),
            zone_info: Set(Some("UTC".to_owned())),
            locale: Set(Some("en-US".to_owned())),
            email_verified: Set(true),
            phone_number: Set(Some("+12025550123".to_owned())),
            phone_number_verified: Set(Some(true)),
            address_formatted: Set(Some("1 Main St\nConformance City, CA 94000\nUS".to_owned())),
            address_street_address: Set(Some("1 Main St".to_owned())),
            address_locality: Set(Some("Conformance City".to_owned())),
            address_region: Set(Some("CA".to_owned())),
            address_postal_code: Set(Some("94000".to_owned())),
            address_country: Set(Some("US".to_owned())),
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

    // ── OIDC clients ───────────────────────────────────────────────────────

    for spec in conformance_client_specs() {
        let client_id = ensure_conformance_client(&txn, spec, now).await?;
        ensure_web_platform_redirect_uri(&txn, client_id).await?;
        assign_all_built_in_oidc_scopes(&txn, client_id).await?;
    }

    txn.commit()
        .await
        .map_err(|e| AppError::from_code(CommonErrorCode::InternalError).with_source(e))?;

    Ok(())
}

async fn ensure_dynamic_registration_enabled(
    db: &impl sea_orm::ConnectionTrait,
    now: chrono::DateTime<Utc>,
) -> Result<(), AppError> {
    let existing = setting::Entity::find()
        .filter(setting::Column::Key.eq(DynamicClientRegistrationSetting::KEY))
        .one(db)
        .await
        .map_err(|error| AppError::from_code(CommonErrorCode::InternalError).with_source(error))?;

    let enabled = serde_json::json!(true);
    if let Some(row) = existing {
        if row.value != enabled {
            let mut am: setting::ActiveModel = row.into();
            am.value = Set(enabled);
            am.updated_at = Set(Some(now.naive_utc()));
            am.update(db).await.map_err(|error| {
                AppError::from_code(CommonErrorCode::InternalError).with_source(error)
            })?;
        }
        return Ok(());
    }

    setting::ActiveModel {
        oid: Set(Uuid::new_v4()),
        key: Set(DynamicClientRegistrationSetting::KEY.to_owned()),
        value: Set(enabled),
        created_at: Set(now.naive_utc()),
        updated_at: Set(Some(now.naive_utc())),
        ..Default::default()
    }
    .insert(db)
    .await
    .map_err(|error| AppError::from_code(CommonErrorCode::InternalError).with_source(error))?;

    Ok(())
}

fn conformance_client_specs() -> &'static [ConformanceClientSpec] {
    &[
        ConformanceClientSpec {
            oid: BASIC_CLIENT_OID,
            credential_oid: BASIC_CLIENT_CRED_OID,
            name: CONFORMANCE_BASIC_CLIENT_NAME,
            secret: CONFORMANCE_BASIC_CLIENT_SECRET,
            token_endpoint_auth_method: "client_secret_basic",
            grant_types: &["authorization_code", "refresh_token"],
            response_types: &["code"],
        },
        ConformanceClientSpec {
            oid: BASIC_CLIENT_POST_OID,
            credential_oid: BASIC_CLIENT_POST_CRED_OID,
            name: "OpenID Conformance Suite (Basic client_secret_post)",
            secret: CONFORMANCE_BASIC_CLIENT_POST_SECRET,
            token_endpoint_auth_method: "client_secret_post",
            grant_types: &["authorization_code", "refresh_token"],
            response_types: &["code"],
        },
        ConformanceClientSpec {
            oid: IMPLICIT_CLIENT_OID,
            credential_oid: IMPLICIT_CLIENT_CRED_OID,
            name: CONFORMANCE_IMPLICIT_CLIENT_NAME,
            secret: CONFORMANCE_IMPLICIT_CLIENT_SECRET,
            token_endpoint_auth_method: "client_secret_basic",
            grant_types: &["implicit"],
            response_types: &["id_token", "id_token token"],
        },
        ConformanceClientSpec {
            oid: IMPLICIT_CLIENT_POST_OID,
            credential_oid: IMPLICIT_CLIENT_POST_CRED_OID,
            name: "OpenID Conformance Suite (Implicit client_secret_post)",
            secret: CONFORMANCE_IMPLICIT_CLIENT_POST_SECRET,
            token_endpoint_auth_method: "client_secret_post",
            grant_types: &["implicit"],
            response_types: &["id_token", "id_token token"],
        },
        ConformanceClientSpec {
            oid: HYBRID_CLIENT_OID,
            credential_oid: HYBRID_CLIENT_CRED_OID,
            name: CONFORMANCE_HYBRID_CLIENT_NAME,
            secret: CONFORMANCE_HYBRID_CLIENT_SECRET,
            token_endpoint_auth_method: "client_secret_basic",
            grant_types: &["authorization_code", "implicit", "refresh_token"],
            response_types: &["code id_token", "code token", "code id_token token"],
        },
        ConformanceClientSpec {
            oid: HYBRID_CLIENT_POST_OID,
            credential_oid: HYBRID_CLIENT_POST_CRED_OID,
            name: "OpenID Conformance Suite (Hybrid client_secret_post)",
            secret: CONFORMANCE_HYBRID_CLIENT_POST_SECRET,
            token_endpoint_auth_method: "client_secret_post",
            grant_types: &["authorization_code", "implicit", "refresh_token"],
            response_types: &["code id_token", "code token", "code id_token token"],
        },
    ]
}

async fn ensure_conformance_client(
    db: &impl sea_orm::ConnectionTrait,
    spec: &ConformanceClientSpec,
    now: chrono::DateTime<Utc>,
) -> Result<i64, AppError> {
    let client_oid: Uuid = spec.oid.parse().expect("client OID literal is valid");
    let credential_oid: Uuid = spec
        .credential_oid
        .parse()
        .expect("client credential OID literal is valid");

    let existing_client = client::Entity::find()
        .filter(client::Column::Oid.eq(client_oid))
        .one(db)
        .await
        .map_err(|error| AppError::from_code(CommonErrorCode::InternalError).with_source(error))?;

    let client_id = if let Some(row) = existing_client {
        if row.protocol != "openid_connect" || row.name != spec.name {
            let mut am: client::ActiveModel = row.clone().into();
            am.protocol = Set("openid_connect".to_owned());
            am.name = Set(spec.name.to_owned());
            am.updated_at = Set(Some(now.naive_utc()));
            am.update(db).await.map_err(|error| {
                AppError::from_code(CommonErrorCode::InternalError).with_source(error)
            })?;
        }
        row.id
    } else {
        client::ActiveModel {
            oid: Set(client_oid),
            protocol: Set("openid_connect".to_owned()),
            name: Set(spec.name.to_owned()),
            names: Set(None),
            description: Set(None),
            created_at: Set(now.naive_utc()),
            updated_at: Set(None),
            ..Default::default()
        }
        .insert(db)
        .await
        .map_err(|error| AppError::from_code(CommonErrorCode::InternalError).with_source(error))?
        .id
    };

    ensure_conformance_oidc_metadata(db, client_id, spec, now).await?;
    ensure_conformance_client_secret(db, client_id, credential_oid, spec.secret, now).await?;

    Ok(client_id)
}

async fn ensure_conformance_oidc_metadata(
    db: &impl sea_orm::ConnectionTrait,
    client_id: i64,
    spec: &ConformanceClientSpec,
    now: chrono::DateTime<Utc>,
) -> Result<(), AppError> {
    let values = conformance_oidc_metadata_values(spec);

    let existing = client_open_id_connect::Entity::find()
        .filter(client_open_id_connect::Column::ClientId.eq(client_id))
        .one(db)
        .await
        .map_err(|error| AppError::from_code(CommonErrorCode::InternalError).with_source(error))?;

    if let Some(row) = existing {
        if row.grant_types.as_ref() != Some(&values.grant_types)
            || row.response_types.as_ref() != Some(&values.response_types)
            || row.token_endpoint_auth_method != values.token_endpoint_auth_method
            || row.post_logout_redirect_uris != values.post_logout_redirect_uris
            || row.frontchannel_logout_uri != values.frontchannel_logout_uri
            || row.frontchannel_logout_session_required
                != values.frontchannel_logout_session_required
            || row.backchannel_logout_uri != values.backchannel_logout_uri
            || row.backchannel_logout_session_required != values.backchannel_logout_session_required
            || row.settings != values.settings
        {
            let mut am: client_open_id_connect::ActiveModel = row.into();
            am.grant_types = Set(Some(values.grant_types));
            am.response_types = Set(Some(values.response_types));
            am.token_endpoint_auth_method = Set(values.token_endpoint_auth_method);
            am.post_logout_redirect_uris = Set(values.post_logout_redirect_uris);
            am.frontchannel_logout_uri = Set(values.frontchannel_logout_uri);
            am.frontchannel_logout_session_required =
                Set(values.frontchannel_logout_session_required);
            am.backchannel_logout_uri = Set(values.backchannel_logout_uri);
            am.backchannel_logout_session_required =
                Set(values.backchannel_logout_session_required);
            am.settings = Set(values.settings);
            am.updated_at = Set(Some(now.into()));
            am.update(db).await.map_err(|error| {
                AppError::from_code(CommonErrorCode::InternalError).with_source(error)
            })?;
        }

        return Ok(());
    }

    client_open_id_connect::ActiveModel {
        client_id: Set(client_id),
        grant_types: Set(Some(values.grant_types)),
        response_types: Set(Some(values.response_types)),
        token_endpoint_auth_method: Set(values.token_endpoint_auth_method),
        post_logout_redirect_uris: Set(values.post_logout_redirect_uris),
        frontchannel_logout_uri: Set(values.frontchannel_logout_uri),
        frontchannel_logout_session_required: Set(values.frontchannel_logout_session_required),
        backchannel_logout_uri: Set(values.backchannel_logout_uri),
        backchannel_logout_session_required: Set(values.backchannel_logout_session_required),
        settings: Set(values.settings),
        created_at: Set(now.into()),
        updated_at: Set(None),
        ..Default::default()
    }
    .insert(db)
    .await
    .map_err(|error| AppError::from_code(CommonErrorCode::InternalError).with_source(error))?;

    Ok(())
}

fn conformance_oidc_metadata_values(spec: &ConformanceClientSpec) -> ConformanceOidcMetadataValues {
    ConformanceOidcMetadataValues {
        grant_types: serde_json::json!(spec.grant_types),
        response_types: serde_json::json!(spec.response_types),
        token_endpoint_auth_method: Some(spec.token_endpoint_auth_method.to_owned()),
        post_logout_redirect_uris: Some(conformance_post_logout_redirect_uris()),
        frontchannel_logout_uri: Some(conformance_frontchannel_logout_uri()),
        frontchannel_logout_session_required: Some(true),
        backchannel_logout_uri: Some(conformance_backchannel_logout_uri()),
        backchannel_logout_session_required: Some(true),
        settings: conformance_client_settings(),
    }
}

async fn ensure_conformance_client_secret(
    db: &impl sea_orm::ConnectionTrait,
    client_id: i64,
    credential_oid: Uuid,
    secret: &str,
    now: chrono::DateTime<Utc>,
) -> Result<(), AppError> {
    let secret_json = serde_json::json!({ "secret": secret });
    let expires_at = chrono::DateTime::parse_from_rfc3339("9999-12-31T23:59:59+00:00")
        .expect("non-expiring timestamp literal is valid");

    let existing = client_open_id_connect_credential::Entity::find()
        .filter(client_open_id_connect_credential::Column::Oid.eq(credential_oid))
        .one(db)
        .await
        .map_err(|error| AppError::from_code(CommonErrorCode::InternalError).with_source(error))?;

    if let Some(row) = existing {
        if row.client_id != client_id
            || row.r#type != "client_secret"
            || row.data != secret_json
            || row.hint != secret
            || row.expires_at != expires_at
            || row.revoked_at.is_some()
        {
            let mut am: client_open_id_connect_credential::ActiveModel = row.into();
            am.client_id = Set(client_id);
            am.r#type = Set("client_secret".to_owned());
            am.data = Set(secret_json);
            am.hint = Set(secret.to_owned());
            am.expires_at = Set(expires_at);
            am.revoked_at = Set(None);
            am.updated_at = Set(Some(now.into()));
            am.update(db).await.map_err(|error| {
                AppError::from_code(CommonErrorCode::InternalError).with_source(error)
            })?;
        }

        return Ok(());
    }

    client_open_id_connect_credential::ActiveModel {
        oid: Set(credential_oid),
        client_id: Set(client_id),
        r#type: Set("client_secret".to_owned()),
        data: Set(secret_json),
        hint: Set(secret.to_owned()),
        expires_at: Set(expires_at),
        revoked_at: Set(None),
        created_at: Set(now.into()),
        updated_at: Set(None),
        ..Default::default()
    }
    .insert(db)
    .await
    .map_err(|error| AppError::from_code(CommonErrorCode::InternalError).with_source(error))?;

    Ok(())
}

fn conformance_redirect_uris() -> serde_json::Value {
    serde_json::json!([
        "https://localhost.emobix.co.uk:8443/test/a/identity/callback",
        "https://localhost.emobix.co.uk:8443/test/a/identity-formpost-basic/callback",
        "https://localhost.emobix.co.uk:8443/test/a/identity-formpost-implicit/callback",
        "https://localhost.emobix.co.uk:8443/test/a/identity-formpost-hybrid/callback",
        "https://localhost.emobix.co.uk:8443/test/a/identity-rp-init-logout/callback",
        "https://localhost.emobix.co.uk:8443/test/a/identity-session/callback",
        "https://localhost.emobix.co.uk:8443/test/a/identity-frontchannel/callback",
        "https://localhost.emobix.co.uk:8443/test/a/identity-backchannel/callback",
        "https://localhost.emobix.co.uk:8443/test/a/identity-config/callback"
    ])
}

fn conformance_post_logout_redirect_uris() -> serde_json::Value {
    serde_json::json!([
        "https://localhost.emobix.co.uk:8443/test/a/identity-rp-init-logout/post_logout_redirect",
        "https://localhost.emobix.co.uk:8443/test/a/identity-session/post_logout_redirect",
        "https://localhost.emobix.co.uk:8443/test/a/identity-backchannel/post_logout_redirect"
    ])
}

fn conformance_frontchannel_logout_uri() -> String {
    "https://localhost.emobix.co.uk:8443/test/a/identity-frontchannel/frontchannel_logout"
        .to_owned()
}

fn conformance_backchannel_logout_uri() -> String {
    "https://localhost.emobix.co.uk:8443/test/a/identity-backchannel/backchannel_logout".to_owned()
}

fn conformance_client_settings() -> serde_json::Value {
    serde_json::json!({
        "skip_consent": true,
        "allow_public_client_flow": false
    })
}

async fn ensure_web_platform_redirect_uri(
    db: &impl sea_orm::ConnectionTrait,
    client_id: i64,
) -> Result<(), AppError> {
    let existing = client_platform::Entity::find()
        .filter(client_platform::Column::ClientId.eq(client_id))
        .filter(client_platform::Column::Platform.eq("web"))
        .one(db)
        .await
        .map_err(|error| AppError::from_code(CommonErrorCode::InternalError).with_source(error))?;

    if let Some(row) = existing {
        if row.redirect_uris.as_ref() != Some(&conformance_redirect_uris()) {
            let mut am: client_platform::ActiveModel = row.into();
            am.redirect_uris = Set(Some(conformance_redirect_uris()));
            am.update(db).await.map_err(|error| {
                AppError::from_code(CommonErrorCode::InternalError).with_source(error)
            })?;
        }

        return Ok(());
    }

    client_platform::ActiveModel {
        client_id: Set(client_id),
        platform: Set("web".to_owned()),
        redirect_uris: Set(Some(conformance_redirect_uris())),
        created_at: Set(Utc::now().into()),
        updated_at: Set(None),
        ..Default::default()
    }
    .insert(db)
    .await
    .map_err(|error| AppError::from_code(CommonErrorCode::InternalError).with_source(error))?;

    Ok(())
}

/// Hash `CONFORMANCE_PASSWORD` with the same Argon2id defaults the app uses,
/// and return the serialised `Password` JSON value ready for the DB.
fn hash_conformance_password() -> Result<serde_json::Value, AppError> {
    use argon2::{
        Argon2, PasswordHasher,
        password_hash::{SaltString, rand_core::OsRng},
    };
    use identity_domain::user::password::{
        Argon2Options, Argon2Password, Argon2Variant, Argon2Version, Password,
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

async fn assign_all_built_in_oidc_scopes(
    db: &impl sea_orm::ConnectionTrait,
    client_id: i64,
) -> Result<(), AppError> {
    use crate::database::seed::scope::OPENID_CONNECT_PROTOCOL;

    let scopes = scope::Entity::find()
        .filter(scope::Column::Protocol.eq(OPENID_CONNECT_PROTOCOL))
        .all(db)
        .await
        .map_err(|error| AppError::from_code(CommonErrorCode::InternalError).with_source(error))?;

    for scope in scopes {
        let existing = client_scope::Entity::find()
            .filter(client_scope::Column::ClientId.eq(client_id))
            .filter(client_scope::Column::ScopeId.eq(scope.id))
            .one(db)
            .await
            .map_err(|error| {
                AppError::from_code(CommonErrorCode::InternalError).with_source(error)
            })?;

        if existing.is_none() {
            client_scope::ActiveModel {
                client_id: Set(client_id),
                scope_id: Set(scope.id),
                ..Default::default()
            }
            .insert(db)
            .await
            .map_err(|error| {
                AppError::from_code(CommonErrorCode::InternalError).with_source(error)
            })?;
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    #[test]
    fn conformance_redirect_uris_include_active_plan_aliases() {
        let redirect_uris = super::conformance_redirect_uris();
        let redirect_uris = redirect_uris.as_array().unwrap();
        let redirect_uris = redirect_uris
            .iter()
            .map(|value| value.as_str().unwrap())
            .collect::<Vec<_>>();

        assert!(
            redirect_uris.contains(&"https://localhost.emobix.co.uk:8443/test/a/identity/callback")
        );
        assert!(redirect_uris.contains(
            &"https://localhost.emobix.co.uk:8443/test/a/identity-formpost-basic/callback"
        ));
        assert!(redirect_uris.contains(
            &"https://localhost.emobix.co.uk:8443/test/a/identity-formpost-implicit/callback"
        ));
        assert!(redirect_uris.contains(
            &"https://localhost.emobix.co.uk:8443/test/a/identity-formpost-hybrid/callback"
        ));
        assert!(redirect_uris.contains(
            &"https://localhost.emobix.co.uk:8443/test/a/identity-rp-init-logout/callback"
        ));
        assert!(
            redirect_uris
                .contains(&"https://localhost.emobix.co.uk:8443/test/a/identity-session/callback")
        );
        assert!(redirect_uris.contains(
            &"https://localhost.emobix.co.uk:8443/test/a/identity-frontchannel/callback"
        ));
        assert!(
            redirect_uris.contains(
                &"https://localhost.emobix.co.uk:8443/test/a/identity-backchannel/callback"
            )
        );
        assert!(
            redirect_uris
                .contains(&"https://localhost.emobix.co.uk:8443/test/a/identity-config/callback")
        );
    }

    #[test]
    fn conformance_post_logout_redirect_uris_include_rp_init_logout_alias() {
        let uris = super::conformance_post_logout_redirect_uris();
        let uris = uris.as_array().unwrap();
        let uris = uris
            .iter()
            .map(|value| value.as_str().unwrap())
            .collect::<Vec<_>>();

        assert!(uris.contains(
            &"https://localhost.emobix.co.uk:8443/test/a/identity-rp-init-logout/post_logout_redirect"
        ));
    }

    #[test]
    fn conformance_post_logout_redirect_uris_include_session_alias() {
        let uris = super::conformance_post_logout_redirect_uris();
        let uris = uris.as_array().unwrap();
        let uris = uris
            .iter()
            .map(|value| value.as_str().unwrap())
            .collect::<Vec<_>>();

        assert!(uris.contains(
            &"https://localhost.emobix.co.uk:8443/test/a/identity-session/post_logout_redirect"
        ));
    }

    #[test]
    fn conformance_post_logout_redirect_uris_include_backchannel_alias() {
        let uris = super::conformance_post_logout_redirect_uris();
        let uris = uris.as_array().unwrap();
        let uris = uris
            .iter()
            .map(|value| value.as_str().unwrap())
            .collect::<Vec<_>>();

        assert!(uris.contains(
            &"https://localhost.emobix.co.uk:8443/test/a/identity-backchannel/post_logout_redirect"
        ));
    }

    #[test]
    fn conformance_oidc_metadata_values_include_post_logout_redirect_uris() {
        let values = super::conformance_oidc_metadata_values(&super::conformance_client_specs()[0]);

        assert_eq!(
            values.post_logout_redirect_uris,
            Some(super::conformance_post_logout_redirect_uris())
        );
    }

    #[test]
    fn conformance_oidc_metadata_values_include_frontchannel_logout_metadata() {
        let values = super::conformance_oidc_metadata_values(&super::conformance_client_specs()[0]);

        assert_eq!(
            values.frontchannel_logout_uri.as_deref(),
            Some(
                "https://localhost.emobix.co.uk:8443/test/a/identity-frontchannel/frontchannel_logout"
            )
        );
        assert_eq!(values.frontchannel_logout_session_required, Some(true));
    }

    #[test]
    fn conformance_oidc_metadata_values_include_backchannel_logout_metadata() {
        let values = super::conformance_oidc_metadata_values(&super::conformance_client_specs()[0]);

        assert_eq!(
            values.backchannel_logout_uri.as_deref(),
            Some(
                "https://localhost.emobix.co.uk:8443/test/a/identity-backchannel/backchannel_logout"
            )
        );
        assert_eq!(values.backchannel_logout_session_required, Some(true));
    }
}
