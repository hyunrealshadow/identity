//! Protected Console OAuth client seed.
//!
//! Installation/startup supplies explicitly validated HTTPS origin, issuer
//! and callback values. New installation provisions this in the owner transaction.
//!
//! The Console client is a public, code-only OIDC client:
//! - `authorization_code` grant and `code` response only;
//! - `token_endpoint_auth_methods = ["none"]` with the public flow enabled;
//! - S256 PKCE is required by the public code flow;
//! - no client secret or any other credential is inserted;
//! - allowed scope ceiling: `openid profile email`, `account.read` (to follow
//!   the operator's account preferences such as the theme) and the exact
//!   trusted management scopes, reconciled on every start so upgrades keep the
//!   system-managed client usable;
//! - the GraphQL resource covers those scopes.

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use identity_domain::{
    authorization::catalog::{ManagementScope, validate_catalog},
    openid_connect::{ApiScope, ScopeSet, model::claim::StandardScopes},
};
use sea_orm::{
    ActiveModelTrait, ColumnTrait, ConnectionTrait, DatabaseConnection, DatabaseTransaction,
    DbBackend, EntityTrait, QueryFilter, Set, Statement, TransactionTrait, Value,
};
use serde_json::json;
use url::Url;
use uuid::Uuid;

use super::{
    Seed,
    oauth_resource::{ensure_graphql_resource_coverage, graphql_resource_oid},
    scope::resolve_builtin_scope_ids,
};
use crate::{
    application::{
        error::{AppError, codes::common::CommonErrorCode},
        setting::ConsoleClientIdSetting,
    },
    database::{
        audit,
        entity::{
            client,
            client::{Column as ClientColumn, Entity as ClientEntity},
            client_openid_connect,
            client_openid_connect::{
                Column as ClientOpenIdConnectColumn, Entity as ClientOpenIdConnectEntity,
            },
            client_openid_connect_platform,
            client_openid_connect_platform::{
                Column as ClientOpenIdConnectPlatformColumn,
                Entity as ClientOpenIdConnectPlatformEntity,
            },
            client_scope,
            client_scope::{Column as ClientScopeColumn, Entity as ClientScopeEntity},
        },
        repository::setting::read_setting,
    },
};

pub use identity_domain::client::built_in::CONSOLE_CLIENT_NAME;
pub const CONSOLE_CLIENT_PROTOCOL: &str = "openid_connect";

/// Base scopes plus every trusted management catalog entry. This is an allowed
/// ceiling, not an automatic grant: effective-permission clipping still decides what a
/// particular authorization receives.
pub fn console_scope_names() -> Vec<&'static str> {
    let mut names = vec![
        StandardScopes::OPENID,
        StandardScopes::PROFILE,
        StandardScopes::EMAIL,
        ApiScope::ACCOUNT_READ,
    ];
    names.extend(ManagementScope::ALL.into_iter().map(|scope| scope.name()));
    names
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConsoleClientSeedConfig {
    pub origin: Url,
    pub issuer: Url,
    pub redirect_uri: Url,
}

impl ConsoleClientSeedConfig {
    /// Validates explicit HTTPS origin/issuer/callback inputs. No default
    /// origin or issuer is invented.
    pub fn new(
        origin: &str,
        issuer: &str,
        redirect_uri: &str,
    ) -> Result<Self, ConsoleSeedConfigError> {
        let origin = parse_https_url(origin, "origin")?;
        let issuer = parse_https_url(issuer, "issuer")?;
        let redirect_uri = parse_https_url(redirect_uri, "redirect_uri")?;

        require_origin_root(&origin)?;
        require_no_fragment_or_query(&issuer, "issuer")?;
        require_no_fragment_or_query(&redirect_uri, "redirect_uri")?;

        let origin_authority = authority(&origin);
        if authority(&redirect_uri) != origin_authority {
            return Err(ConsoleSeedConfigError::OriginMismatch);
        }

        Ok(Self {
            origin,
            issuer,
            redirect_uri,
        })
    }
}

fn parse_https_url(value: &str, field: &'static str) -> Result<Url, ConsoleSeedConfigError> {
    let url = Url::parse(value).map_err(|_| ConsoleSeedConfigError::InvalidUrl(field))?;
    if url.scheme() != "https" {
        return Err(ConsoleSeedConfigError::HttpsRequired(field));
    }
    if url.host_str().is_none() || !url.username().is_empty() || url.password().is_some() {
        return Err(ConsoleSeedConfigError::UnsafeAuthority(field));
    }
    Ok(url)
}

fn require_origin_root(url: &Url) -> Result<(), ConsoleSeedConfigError> {
    if url.query().is_some() || url.fragment().is_some() || url.path() != "/" {
        return Err(ConsoleSeedConfigError::OriginMustBeRoot);
    }
    Ok(())
}

fn require_no_fragment_or_query(
    url: &Url,
    field: &'static str,
) -> Result<(), ConsoleSeedConfigError> {
    if url.fragment().is_some() || url.query().is_some() {
        return Err(ConsoleSeedConfigError::QueryOrFragment(field));
    }
    Ok(())
}

fn authority(url: &Url) -> (String, String, Option<u16>) {
    (
        url.scheme().to_owned(),
        url.host_str().unwrap_or_default().to_ascii_lowercase(),
        url.port_or_known_default(),
    )
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ConsoleSeedConfigError {
    #[error("console client {0} URL is invalid")]
    InvalidUrl(&'static str),
    #[error("console client {0} URL must use HTTPS")]
    HttpsRequired(&'static str),
    #[error("console client {0} URL has an unsafe authority")]
    UnsafeAuthority(&'static str),
    #[error("console client origin must be an HTTPS origin root")]
    OriginMustBeRoot,
    #[error("console client {0} URL must not carry a query or fragment")]
    QueryOrFragment(&'static str),
    #[error("console client origin, issuer and redirect URI must share one authority")]
    OriginMismatch,
}

/// Seed helper. Construct with explicit validated inputs; it carries no secret.
pub struct ConsoleClientSeed {
    config: ConsoleClientSeedConfig,
}

impl ConsoleClientSeed {
    pub fn new(config: ConsoleClientSeedConfig) -> Self {
        Self { config }
    }

    #[must_use]
    pub fn config(&self) -> &ConsoleClientSeedConfig {
        &self.config
    }
}

#[async_trait]
impl Seed for ConsoleClientSeed {
    fn name(&self) -> &'static str {
        "console_client"
    }

    async fn run(&self, db: &DatabaseConnection) -> Result<(), AppError> {
        ensure_console_client(db, &self.config).await
    }
}

/// Idempotently reconciles the Console client, its metadata/platform,
/// scope assignments and GraphQL resource coverage. Credentials are never
/// written.
pub async fn ensure_console_client(
    db: &DatabaseConnection,
    config: &ConsoleClientSeedConfig,
) -> Result<(), AppError> {
    let txn = db.begin().await.map_err(AppError::internal)?;
    ensure_console_client_in_transaction(&txn, config).await?;
    txn.commit().await.map_err(AppError::internal)?;
    Ok(())
}

pub async fn ensure_console_client_in_transaction(
    db: &DatabaseTransaction,
    config: &ConsoleClientSeedConfig,
) -> Result<(), AppError> {
    let oid = read_setting::<ConsoleClientIdSetting, _>(db)
        .await?
        .ok_or_else(|| AppError::from_code(CommonErrorCode::InternalError))?;
    let existing = ClientEntity::find()
        .filter(ClientColumn::Oid.eq(oid))
        .one(db)
        .await
        .map_err(AppError::internal)?
        .ok_or_else(|| AppError::from_code(CommonErrorCode::InternalError))?;
    if !existing.built_in || existing.protocol != CONSOLE_CLIENT_PROTOCOL {
        return Err(AppError::from_code(CommonErrorCode::Forbidden));
    }
    configure_console_client(db, config, existing.id, oid, false).await
}

/// Called only by installation, inside its transaction and provisioning lock.
pub async fn provision_console_client_in_transaction(
    db: &DatabaseTransaction,
    config: &ConsoleClientSeedConfig,
    oid: Uuid,
) -> Result<(), AppError> {
    let client = client::ActiveModel {
        oid: Set(oid),
        protocol: Set(CONSOLE_CLIENT_PROTOCOL.to_owned()),
        name: Set(CONSOLE_CLIENT_NAME.to_owned()),
        names: Set(None),
        description: Set(Some("Protected Identity console client".to_owned())),
        built_in: Set(true),
        created_at: Set(Utc::now().into()),
        updated_at: Set(None),
        ..Default::default()
    }
    .insert(db)
    .await
    .map_err(AppError::internal)?;
    configure_console_client(db, config, client.id, oid, true).await
}

async fn configure_console_client(
    db: &DatabaseTransaction,
    config: &ConsoleClientSeedConfig,
    client_id: i64,
    console_oid: Uuid,
    created: bool,
) -> Result<(), AppError> {
    validate_catalog().map_err(AppError::internal)?;
    ensure_graphql_resource_coverage(db).await?;
    let graphql_resource_oid = graphql_resource_oid(db).await?;
    let now = Utc::now();
    let scope_names = console_scope_names();
    let scope_ids = ensure_scope_rows(db, &scope_names, graphql_resource_oid).await?;
    let mut material_change = created;
    material_change |= ensure_oidc_metadata(db, client_id, &config.redirect_uri, now).await?;
    material_change |= ensure_web_platform(db, client_id, &config.redirect_uri, now).await?;
    // The Console is system-managed: every start reconciles its ceiling to the
    // current catalog, so an upgrade that needs a new scope keeps it usable.
    material_change |= replace_client_scopes(db, client_id, &scope_ids).await?;
    // CORS origins are derived only from the explicitly configured Console origin.
    let origin = config.origin.origin().ascii_serialization();
    let cors = db
        .execute_raw(Statement::from_sql_and_values(
            DbBackend::Postgres,
            "INSERT INTO client_openid_connect_cors_origin(client_id,origin) VALUES($1,$2) ON CONFLICT(client_id,origin) DO NOTHING",
            [Value::from(client_id), Value::from(origin)],
        ))
        .await
        .map_err(AppError::internal)?;
    material_change |= cors.rows_affected() > 0;

    if material_change {
        audit::record(db, "client.update", "client", console_oid)
            .await
            .map_err(AppError::internal)?;
    }
    Ok(())
}

pub(super) async fn ensure_scope_rows(
    db: &impl ConnectionTrait,
    names: &[&'static str],
    graphql_resource_oid: uuid::Uuid,
) -> Result<Vec<i64>, AppError> {
    // Names may be exact concrete codes or trusted input selectors such as
    // `account.*` and `management.*`; only concrete rows are assigned.
    resolve_builtin_scope_ids(db, names, graphql_resource_oid).await
}

async fn ensure_oidc_metadata(
    db: &impl ConnectionTrait,
    client_id: i64,
    redirect_uri: &Url,
    now: DateTime<Utc>,
) -> Result<bool, AppError> {
    let settings = json!({
        "skip_consent": true,
        "cors_enabled": true,
        "oauth_version": "2.1",
        "allow_public_client_flow": true,
        "require_pushed_authorization_requests": false,
        // The management shell reads its operator summary from the signed
        // OIDC claims, without requiring account self-service API scopes.
        "include_scoped_claims_in_id_token": true,
        "include_scoped_claims_in_access_token": false
    });
    let logout_uris = json!([redirect_uri
        .join("signed-out")
        .map_err(AppError::internal)?
        .as_str()]);
    let grant_types = json!(["authorization_code"]);
    let response_types = json!(["code"]);
    let token_endpoint_auth_methods = json!(["none"]);

    let existing = ClientOpenIdConnectEntity::find()
        .filter(ClientOpenIdConnectColumn::ClientId.eq(client_id))
        .one(db)
        .await
        .map_err(AppError::internal)?;
    if let Some(existing) = existing {
        if existing.post_logout_redirect_uris == Some(logout_uris.clone())
            && existing.grant_types == Some(grant_types.clone())
            && existing.response_types == Some(response_types.clone())
            && existing.token_endpoint_auth_methods == Some(token_endpoint_auth_methods.clone())
            && existing.settings == settings
        {
            return Ok(false);
        }
        let mut active: client_openid_connect::ActiveModel = existing.into();
        active.post_logout_redirect_uris = Set(Some(logout_uris));
        active.grant_types = Set(Some(grant_types));
        active.response_types = Set(Some(response_types));
        active.token_endpoint_auth_methods = Set(Some(token_endpoint_auth_methods));
        active.settings = Set(settings);
        active.updated_at = Set(Some(now.into()));
        active.update(db).await.map_err(AppError::internal)?;
        return Ok(true);
    }
    client_openid_connect::ActiveModel {
        client_id: Set(client_id),
        post_logout_redirect_uris: Set(Some(logout_uris)),
        grant_types: Set(Some(grant_types)),
        response_types: Set(Some(response_types)),
        token_endpoint_auth_methods: Set(Some(token_endpoint_auth_methods)),
        settings: Set(settings),
        created_at: Set(now.into()),
        updated_at: Set(None),
        ..Default::default()
    }
    .insert(db)
    .await
    .map_err(AppError::internal)?;
    Ok(true)
}

async fn ensure_web_platform(
    db: &impl ConnectionTrait,
    client_id: i64,
    redirect_uri: &Url,
    now: DateTime<Utc>,
) -> Result<bool, AppError> {
    let redirect_uris = json!([redirect_uri.as_str()]);
    let existing = ClientOpenIdConnectPlatformEntity::find()
        .filter(ClientOpenIdConnectPlatformColumn::ClientId.eq(client_id))
        .filter(ClientOpenIdConnectPlatformColumn::Platform.eq("web"))
        .one(db)
        .await
        .map_err(AppError::internal)?;
    if let Some(existing) = existing {
        if existing.redirect_uris == Some(redirect_uris.clone()) {
            return Ok(false);
        }
        let mut active: client_openid_connect_platform::ActiveModel = existing.into();
        active.redirect_uris = Set(Some(redirect_uris));
        active.updated_at = Set(Some(now.into()));
        active.update(db).await.map_err(AppError::internal)?;
        return Ok(true);
    }
    client_openid_connect_platform::ActiveModel {
        client_id: Set(client_id),
        platform: Set("web".to_owned()),
        redirect_uris: Set(Some(redirect_uris)),
        created_at: Set(now.into()),
        updated_at: Set(None),
        ..Default::default()
    }
    .insert(db)
    .await
    .map_err(AppError::internal)?;
    Ok(true)
}

/// Make the client's scope assignments exactly `scope_ids`; returns whether
/// anything changed. Shared by the system-managed client seeds.
pub(super) async fn replace_client_scopes(
    db: &impl ConnectionTrait,
    client_id: i64,
    scope_ids: &[i64],
) -> Result<bool, AppError> {
    let mut changed = false;
    let existing = ClientScopeEntity::find()
        .filter(ClientScopeColumn::ClientId.eq(client_id))
        .all(db)
        .await
        .map_err(AppError::internal)?;
    for row in existing {
        if !scope_ids.contains(&row.scope_id) {
            ClientScopeEntity::delete_by_id(row.id)
                .exec(db)
                .await
                .map_err(AppError::internal)?;
            changed = true;
        }
    }
    let kept = ClientScopeEntity::find()
        .filter(ClientScopeColumn::ClientId.eq(client_id))
        .all(db)
        .await
        .map_err(AppError::internal)?
        .into_iter()
        .map(|row| row.scope_id)
        .collect::<Vec<_>>();
    for scope_id in scope_ids {
        if !kept.contains(scope_id) {
            client_scope::ActiveModel {
                client_id: Set(client_id),
                scope_id: Set(*scope_id),
                ..Default::default()
            }
            .insert(db)
            .await
            .map_err(AppError::internal)?;
            changed = true;
        }
    }
    Ok(changed)
}

/// Parse the fixed scope ceiling as a domain set. Used by source tests.
#[must_use]
pub fn console_scope_set() -> ScopeSet {
    ScopeSet::parse(&console_scope_names().join(" ")).expect("console scope ceiling is valid")
}

#[cfg(test)]
mod tests {
    use super::{ConsoleClientSeedConfig, ConsoleSeedConfigError};

    #[test]
    fn supports_separate_https_issuer_and_console_origins() {
        let config = ConsoleClientSeedConfig::new(
            "https://console.example.com",
            "https://issuer.example.com",
            "https://console.example.com/callback",
        )
        .unwrap();
        assert_eq!(config.origin.as_str(), "https://console.example.com/");

        for (origin, issuer, callback, error) in [
            (
                "http://console.example.com",
                "http://console.example.com",
                "http://console.example.com/callback",
                ConsoleSeedConfigError::HttpsRequired("origin"),
            ),
            (
                "https://console.example.com",
                "https://issuer.example.com",
                "https://elsewhere.example.com/callback",
                ConsoleSeedConfigError::OriginMismatch,
            ),
            (
                "https://console.example.com",
                "https://console.example.com",
                "https://console.example.com/callback#fragment",
                ConsoleSeedConfigError::QueryOrFragment("redirect_uri"),
            ),
            (
                "https://user:pass@console.example.com",
                "https://console.example.com",
                "https://console.example.com/callback",
                ConsoleSeedConfigError::UnsafeAuthority("origin"),
            ),
        ] {
            assert_eq!(
                ConsoleClientSeedConfig::new(origin, issuer, callback).unwrap_err(),
                error
            );
        }
    }

    #[test]
    fn origin_must_be_a_root() {
        assert_eq!(
            ConsoleClientSeedConfig::new(
                "https://console.example.com/subpath",
                "https://console.example.com",
                "https://console.example.com/callback",
            )
            .unwrap_err(),
            ConsoleSeedConfigError::OriginMustBeRoot
        );
    }
}
