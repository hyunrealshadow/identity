use async_trait::async_trait;
use base64::{Engine as _, engine::general_purpose::STANDARD};
use chrono::Utc;
use identity_domain::{
    authorization::{RequestId, catalog::AdministratorRole},
    rbac as identity_domain_rbac,
    rbac::GroupMembershipOid,
    user::normalization::{normalize_email, normalize_username},
};
use rand::{RngExt, rng};
use sea_orm::{
    ActiveModelTrait, ColumnTrait, Condition, ConnectionTrait, DatabaseConnection, DbBackend,
    EntityTrait, QueryFilter, QuerySelect, QueryTrait, Set, Statement, TransactionTrait,
};
use serde_json::{json, to_value};
use url::Url;
use uuid::Uuid;

use super::authorization_lifecycle;
use crate::{
    application::{
        error::{
            AppError,
            codes::{common::CommonErrorCode, install::InstallErrorCode},
        },
        install::{InstallRepository, InstallationData},
        key::rotation::KEY_LIFETIME,
        setting::InstallationSettings,
        user::CredentialType,
    },
    database::{
        owner_bootstrap,
        query::advisory_transaction_lock,
        seed::{console, console::ConsoleClientSeedConfig, rbac},
    },
    domain::{
        key::{KeyData, KeyType, SymmetricKeyAlgorithm, SymmetricKeyData},
        openid_connect::{
            API_RESOURCE, GrantType, OpenIdConnectCredentialData, ResponseType, SubjectType,
            TokenEndpointAuthMethod,
        },
    },
    infrastructure::{
        crypto::key::generate_all_jwks_for_key,
        database::{
            entity::{
                client, client_openid_connect, client_openid_connect_credential,
                client_openid_connect_platform, client_scope,
                client_scope::Entity as ClientScopeEntity,
                key, key_jwk,
                key_jwk::Entity as KeyJwkEntity,
                resource::{Column as ResourceColumn, Entity as ResourceEntity},
                scope::{Column as ScopeColumn, Entity as ScopeEntity},
                user,
                user::{Column as UserColumn, Entity as UserEntity},
                user_credential,
            },
            repository::{
                openid_connect_credential::serialize_data as serialize_credential_data,
                setting::{read_section, write_settings},
            },
        },
    },
    observability::context,
};

pub struct InstallRepositoryImpl {
    db: DatabaseConnection,
    /// Startup/process configuration, used only when the installation input
    /// itself does not carry a console origin.
    console: Option<ConsoleClientSeedConfig>,
}

// Deliberately distinct from the process-lifetime startup guard lock.
const INSTALL_TRANSACTION_LOCK_ID: i64 = 841_463_791_178_241_512;

impl InstallRepositoryImpl {
    #[must_use]
    pub fn new(db: DatabaseConnection) -> Self {
        Self { db, console: None }
    }

    pub fn with_console_client_config(mut self, config: Option<ConsoleClientSeedConfig>) -> Self {
        self.console = config;
        self
    }
}

#[async_trait]
impl InstallRepository for InstallRepositoryImpl {
    #[tracing::instrument(skip_all, name = "db.query", fields(db.system = "postgresql", db.operation = "create_installation"))]
    async fn create_installation(&self, data: InstallationData) -> Result<(), AppError> {
        let now = Utc::now();
        let user_oid = data.user_oid;
        let key_oid = data.key_oid;
        let client_oid = data.client_id;
        let normalized_username = normalize_username(&data.username)
            .ok_or_else(|| AppError::from_code(InstallErrorCode::UsernameRequired))?;
        let normalized_email = normalize_email(&data.email)
            .map_err(|_| AppError::from_code(InstallErrorCode::EmailInvalid))?;
        let password_json = to_value(&data.password).map_err(AppError::internal)?;
        let key_json =
            to_value(KeyData::Asymmetric(data.key_data.clone())).map_err(AppError::internal)?;

        let txn = self.db.begin().await.map_err(AppError::internal)?;

        acquire_install_transaction_lock(&txn).await?;
        if read_section::<InstallationSettings, _>(&txn)
            .await?
            .initialized
        {
            return Err(AppError::from_code(InstallErrorCode::AlreadyInitialized));
        }

        if UserEntity::find()
            .filter(UserColumn::NameNormalized.eq(&normalized_username))
            .one(&txn)
            .await
            .map_err(AppError::internal)?
            .is_some()
        {
            return Err(AppError::from_code(InstallErrorCode::UsernameExists));
        }

        if UserEntity::find()
            .filter(UserColumn::EmailNormalized.eq(&normalized_email))
            .one(&txn)
            .await
            .map_err(AppError::internal)?
            .is_some()
        {
            return Err(AppError::from_code(InstallErrorCode::EmailExists));
        }

        let created_user = user::ActiveModel {
            oid: Set(user_oid),
            email: Set(data.email),
            email_normalized: Set(normalized_email),
            name: Set(data.username),
            name_normalized: Set(normalized_username),
            email_verified: Set(true),
            failed_attempts: Set(0),
            enabled: Set(true),
            locked: Set(false),
            locked_until: Set(None),
            created_at: Set(now.into()),
            ..Default::default()
        }
        .insert(&txn)
        .await
        .map_err(AppError::internal)?;

        user_credential::ActiveModel {
            oid: Set(Uuid::new_v4()),
            user_id: Set(created_user.id),
            r#type: Set(CredentialType::Password.to_string()),
            data: Set(password_json),
            created_at: Set(now.into()),
            ..Default::default()
        }
        .insert(&txn)
        .await
        .map_err(AppError::internal)?;

        // The trusted built-in definitions must be present before the first
        // membership references them. The startup seed normally already ran;
        // this idempotent call makes the ordering explicit inside the same
        // installation transaction and cannot adopt a same-name custom object.
        rbac::ensure_built_in_rbac(&txn).await?;

        // The first owner is the user explicitly created by this installation.
        // The membership is written in the same transaction as its credential
        // and initial settings, so a failed installation leaves neither behind.
        let owner_group_oid = identity_domain_rbac::built_in_group_oid(AdministratorRole::Owner);
        let owner_group = txn
            .query_one_raw(Statement::from_sql_and_values(
                DbBackend::Postgres,
                "SELECT id FROM user_group WHERE oid = $1 AND built_in = true AND enabled = true",
                [owner_group_oid.0.into()],
            ))
            .await
            .map_err(AppError::internal)?
            .ok_or_else(|| AppError::from_code(CommonErrorCode::InternalError))?;
        let owner_group_id = owner_group
            .try_get::<i64>("", "id")
            .map_err(AppError::internal)?;
        let membership_oid = GroupMembershipOid::new();
        txn.execute_raw(Statement::from_sql_and_values(
            DbBackend::Postgres,
            "INSERT INTO group_membership(oid, group_id, user_id, granted_by_user_id, reason, \
                enabled, version, created_at) \
             VALUES($1, $2, $3, NULL, 'initial_installation', true, gen_random_uuid(), now())",
            [
                membership_oid.0.into(),
                owner_group_id.into(),
                created_user.id.into(),
            ],
        ))
        .await
        .map_err(AppError::internal)?;
        authorization_lifecycle::renew_user_version_in_txn(&txn, created_user.id)
            .await
            .map_err(AppError::internal)?;
        let request_id = RequestId::new(
            context::current_request_correlation()
                .map(|context| context.request_id)
                .unwrap_or_else(|| Uuid::new_v4().to_string()),
        )
        .expect("generated or validated request ID");
        owner_bootstrap::record_group_membership_audit(
            &txn,
            "rbac.group_membership.install",
            membership_oid.0,
            "initial_installation",
            &request_id,
        )
        .await?;
        // The installation input is authoritative for the console origin, so
        // an installed console is never derived from process configuration.
        let console_config = installation_console_config(
            data.console_url.as_ref(),
            data.issuer.as_ref(),
            self.console.as_ref(),
        )?;
        if let Some(config) = console_config {
            console::provision_console_client_in_transaction(&txn, &config, data.console_client_id)
                .await?;
        }

        let created_client = client::ActiveModel {
            oid: Set(client_oid),
            protocol: Set("openid_connect".to_owned()),
            name: Set("Identity Account".to_owned()),
            names: Set(None),
            description: Set(Some(
                "Built-in account and session management application".to_owned(),
            )),
            built_in: Set(true),
            created_at: Set(now.into()),
            ..Default::default()
        }
        .insert(&txn)
        .await
        .map_err(AppError::internal)?;

        let callback_url = built_in_callback_url(&data.application_url)?;
        let logout_url = built_in_logout_url(&data.application_url)?;
        client_openid_connect::ActiveModel {
            client_id: Set(created_client.id),
            post_logout_redirect_uris: Set(Some(json!([logout_url.as_str()]))),
            response_types: Set(Some(json!([ResponseType::Code]))),
            grant_types: Set(Some(json!([
                GrantType::AuthorizationCode.as_str(),
                GrantType::RefreshToken.as_str()
            ]))),
            subject_type: Set(Some(SubjectType::Public.to_string())),
            token_endpoint_auth_methods: Set(Some(json!([
                TokenEndpointAuthMethod::ClientSecretBasic.to_string()
            ]))),
            settings: Set(json!({
                "skip_consent": true,
                "include_scoped_claims_in_id_token": false,
                "include_scoped_claims_in_access_token": false
            })),
            created_at: Set(now.into()),
            ..Default::default()
        }
        .insert(&txn)
        .await
        .map_err(AppError::internal)?;

        client_openid_connect_platform::ActiveModel {
            client_id: Set(created_client.id),
            platform: Set("web".to_owned()),
            redirect_uris: Set(Some(json!([callback_url.as_str()]))),
            created_at: Set(now.into()),
            ..Default::default()
        }
        .insert(&txn)
        .await
        .map_err(AppError::internal)?;

        let assigned_scope_names = [
            "openid",
            "profile",
            "email",
            "offline_access",
            "account.read",
            "account.update",
            "session.read",
            "session.revoke",
            "password.change",
        ];
        let assigned_scopes = ScopeEntity::find()
            .filter(ScopeColumn::Code.is_in(assigned_scope_names))
            .filter(ScopeColumn::BuiltIn.eq(true))
            .filter(ScopeColumn::Enabled.eq(true))
            .filter(
                Condition::any().add(ScopeColumn::ResourceId.is_null()).add(
                    ScopeColumn::ResourceId.in_subquery(
                        ResourceEntity::find()
                            .select_only()
                            .column(ResourceColumn::Oid)
                            .filter(ResourceColumn::Uri.eq(API_RESOURCE))
                            .into_query(),
                    ),
                ),
            )
            .all(&txn)
            .await
            .map_err(AppError::internal)?;
        if assigned_scopes.len() != assigned_scope_names.len() {
            return Err(AppError::from_code(CommonErrorCode::InternalError));
        }
        ClientScopeEntity::insert_many(assigned_scopes.into_iter().map(|scope| {
            client_scope::ActiveModel {
                client_id: Set(created_client.id),
                scope_id: Set(scope.id),
                created_at: Set(now.into()),
                ..Default::default()
            }
        }))
        .exec(&txn)
        .await
        .map_err(AppError::internal)?;

        let serialized_credential =
            serialize_credential_data(OpenIdConnectCredentialData::ClientSecret {
                secret: data.client_secret,
            });
        client_openid_connect_credential::ActiveModel {
            oid: Set(Uuid::new_v4()),
            client_id: Set(created_client.id),
            r#type: Set(serialized_credential.type_),
            data: Set(serialized_credential.data),
            hint: Set(serialized_credential.hint),
            expires_at: Set((now + data.client_secret_lifetime).into()),
            revoked_at: Set(None),
            created_at: Set(now.into()),
            updated_at: Set(None),
            ..Default::default()
        }
        .insert(&txn)
        .await
        .map_err(AppError::internal)?;

        key::ActiveModel {
            oid: Set(key_oid),
            r#type: Set(KeyType::Asymmetric.to_string()),
            data: Set(key_json),
            expires_at: Set((now + KEY_LIFETIME).into()),
            revoked_at: Set(None),
            created_at: Set(now.into()),
            updated_at: Set(None),
            ..Default::default()
        }
        .insert(&txn)
        .await
        .map_err(AppError::internal)?;

        let jwks = generate_all_jwks_for_key(
            &data.key_data.private_key,
            &key_oid.to_string(),
            data.key_data.certificate.as_deref(),
        )
        .map_err(AppError::internal)?;
        let jwk_models = jwks
            .into_iter()
            .map(|(algorithm, jwk)| {
                to_value(jwk).map(|jwk| key_jwk::ActiveModel {
                    oid: Set(Uuid::new_v4()),
                    key_oid: Set(key_oid),
                    algorithm: Set(algorithm),
                    jwk: Set(jwk),
                    created_at: Set(now.into()),
                    ..Default::default()
                })
            })
            .collect::<Result<Vec<_>, _>>()
            .map_err(AppError::internal)?;
        KeyJwkEntity::insert_many(jwk_models)
            .exec(&txn)
            .await
            .map_err(AppError::internal)?;

        let mut sym_key_bytes = [0u8; 32];
        rng().fill(&mut sym_key_bytes[..]);
        let sym_key_b64 = STANDARD.encode(sym_key_bytes);
        let sym_key_json = to_value(KeyData::Symmetric(SymmetricKeyData {
            key: sym_key_b64,
            algorithm: SymmetricKeyAlgorithm::XChaCha20Poly1305,
        }))
        .map_err(AppError::internal)?;
        key::ActiveModel {
            oid: Set(Uuid::new_v4()),
            r#type: Set(KeyType::Symmetric.to_string()),
            data: Set(sym_key_json),
            expires_at: Set((now + KEY_LIFETIME).into()),
            revoked_at: Set(None),
            created_at: Set(now.into()),
            ..Default::default()
        }
        .insert(&txn)
        .await
        .map_err(AppError::internal)?;

        write_settings(&txn, data.settings).await?;

        txn.commit().await.map_err(AppError::internal)?;

        Ok(())
    }
}

fn installation_console_config(
    console_url: Option<&Url>,
    issuer: Option<&Url>,
    fallback: Option<&ConsoleClientSeedConfig>,
) -> Result<Option<ConsoleClientSeedConfig>, AppError> {
    match (console_url, issuer) {
        (Some(console_url), Some(issuer)) => {
            let console_origin = console_url.origin().ascii_serialization();
            // The canonical Console address has no trailing slash (`/console`),
            // so join relative to it as a directory rather than replacing it.
            let mut base = console_url.clone();
            if !base.path().ends_with('/') {
                base.set_path(&format!("{}/", base.path()));
            }
            ConsoleClientSeedConfig::new(
                &console_origin,
                issuer.as_str(),
                base.join("callback").map_err(AppError::internal)?.as_str(),
            )
            .map(Some)
            .map_err(|_| AppError::from_code(InstallErrorCode::DomainInvalid))
        }
        _ => Ok(fallback.cloned()),
    }
}

async fn acquire_install_transaction_lock<C>(db: &C) -> Result<(), AppError>
where
    C: ConnectionTrait,
{
    db.execute(&advisory_transaction_lock(INSTALL_TRANSACTION_LOCK_ID))
        .await
        .map_err(AppError::internal)?;
    Ok(())
}

fn built_in_callback_url(application_url: &Url) -> Result<Url, AppError> {
    application_url.join("callback").map_err(AppError::internal)
}

fn built_in_logout_url(application_url: &Url) -> Result<Url, AppError> {
    application_url.join("logout").map_err(AppError::internal)
}

#[cfg(test)]
mod tests {
    use sea_orm::{DbBackend, MockDatabase, MockExecResult, Transaction};
    use url::Url;

    use super::{
        INSTALL_TRANSACTION_LOCK_ID, acquire_install_transaction_lock, built_in_callback_url,
        built_in_logout_url, installation_console_config,
    };
    use crate::database::{
        query::advisory_transaction_lock, seed::console::ConsoleClientSeedConfig,
    };

    #[test]
    fn built_in_client_uses_top_level_callback_route() {
        let application_url = Url::parse("https://identity.example/").unwrap();

        assert_eq!(
            built_in_callback_url(&application_url).unwrap().as_str(),
            "https://identity.example/callback"
        );
    }

    #[test]
    fn built_in_client_uses_top_level_logout_route() {
        let application_url = Url::parse("https://identity.example/").unwrap();

        assert_eq!(
            built_in_logout_url(&application_url).unwrap().as_str(),
            "https://identity.example/logout"
        );
    }

    #[test]
    fn installation_console_config_prefers_the_wire_input_over_process_config() {
        let console_url = Url::parse("https://console.example.com").unwrap();
        let issuer = Url::parse("https://identity.example.com").unwrap();
        let process = ConsoleClientSeedConfig::new(
            "https://process-console.example.com",
            "https://process-issuer.example.com",
            "https://process-console.example.com/callback",
        )
        .unwrap();

        let config =
            installation_console_config(Some(&console_url), Some(&issuer), Some(&process)).unwrap();

        let config = config.expect("installation input must provision a console client");
        assert_eq!(config.origin.as_str(), "https://console.example.com/");
        assert_eq!(config.issuer.as_str(), "https://identity.example.com/");
        assert_eq!(
            config.redirect_uri.as_str(),
            "https://console.example.com/callback"
        );
    }

    #[test]
    fn installation_console_config_keeps_the_console_path_in_the_callback() {
        let issuer = Url::parse("https://identity.example.com").unwrap();
        for console_url in [
            "https://identity.example.com/console",
            "https://identity.example.com/console/",
        ] {
            let console_url = Url::parse(console_url).unwrap();
            let config = installation_console_config(Some(&console_url), Some(&issuer), None)
                .unwrap()
                .expect("installation input must provision a console client");
            assert_eq!(
                config.redirect_uri.as_str(),
                "https://identity.example.com/console/callback"
            );
        }
    }

    #[test]
    fn installation_console_config_keeps_the_bootstrap_fallback() {
        let process = ConsoleClientSeedConfig::new(
            "https://process-console.example.com",
            "https://process-issuer.example.com",
            "https://process-console.example.com/callback",
        )
        .unwrap();

        let config = installation_console_config(None, None, Some(&process)).unwrap();

        assert_eq!(config, Some(process));
    }

    #[tokio::test]
    async fn install_lock_is_transaction_scoped() {
        let db = MockDatabase::new(DbBackend::Postgres)
            .append_exec_results([MockExecResult::default()])
            .into_connection();

        acquire_install_transaction_lock(&db).await.unwrap();

        assert_eq!(
            db.into_transaction_log(),
            [Transaction::one(DbBackend::Postgres.build(
                &advisory_transaction_lock(INSTALL_TRANSACTION_LOCK_ID)
            ))]
        );
    }
}
