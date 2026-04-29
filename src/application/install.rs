use std::sync::Arc;

use async_trait::async_trait;

use crate::{
    application::{
        error::{AppError, codes::install::InstallErrorCode},
        setting::runtime::{RefreshableSettingProvider, SettingProvider},
    },
    domain::{
        auth::password::{PasswordHashSetting, PasswordHasher},
        key::{AsymmetricKeyAlgorithm, generator::AsymmetricKeyGenerator},
        setting::installation::{InstallationSetting, InstallationState},
        user::model::Password,
    },
};

#[derive(Debug, Clone)]
pub struct InstallInput {
    pub username: String,
    pub email: String,
    pub password: String,
    pub domain: String,
    pub key_algorithm: AsymmetricKeyAlgorithm,
}

pub struct InstallService {
    pub password_hasher: Arc<dyn PasswordHasher>,
    pub password_hash_options: Arc<dyn SettingProvider<PasswordHashSetting>>,
    pub installation_setting: Arc<dyn RefreshableSettingProvider<InstallationSetting>>,
    pub key_generator: Arc<dyn AsymmetricKeyGenerator>,
    pub certificate_generator: Arc<dyn CertificateGenerator>,
    pub persistence: Arc<dyn InstallPersistence>,
}

pub trait CertificateGenerator: Send + Sync {
    fn generate_self_signed(
        &self,
        private_key_pem: &str,
        domain: &str,
        algorithm: &AsymmetricKeyAlgorithm,
    ) -> Result<String, AppError>;
}

#[derive(Debug, Clone)]
pub struct InstallPersistenceInput {
    pub username: String,
    pub email: String,
    pub password: Password,
    pub domain: String,
    pub key_data: identity_domain::key::AsymmetricKeyData,
}

#[async_trait]
pub trait InstallPersistence: Send + Sync {
    async fn persist_installation(
        &self,
        input: InstallPersistenceInput,
    ) -> Result<InstallationState, AppError>;
}

impl InstallService {
    pub fn is_initialized(&self) -> bool {
        self.installation_setting.current_value().initialized
    }

    pub async fn install(&self, input: InstallInput) -> Result<InstallationState, AppError> {
        if self.is_initialized() {
            return Err(AppError::from_code(InstallErrorCode::AlreadyInitialized));
        }

        let username = normalize_required(&input.username, "username")?;
        let email = normalize_email(&input.email)?;
        let password = normalize_required(&input.password, "password")?;
        let domain = normalize_domain(&input.domain)?;

        input
            .key_algorithm
            .validate()
            .map_err(|_| AppError::from_code(InstallErrorCode::AlgorithmInvalid))?;

        let hash_options = self.password_hash_options.current_value();
        let password = self
            .password_hasher
            .hash(&password, hash_options.as_ref())?;
        let mut key_data =
            self.key_generator
                .generate(&identity_domain::key::generator::AsymmetricKeySpec {
                    algorithm: input.key_algorithm.clone(),
                })?;
        let certificate = self.certificate_generator.generate_self_signed(
            &key_data.private_key,
            &domain,
            &input.key_algorithm,
        )?;
        key_data.certificate = Some(certificate);

        let installation_state = self
            .persistence
            .persist_installation(InstallPersistenceInput {
                username,
                email,
                password,
                domain,
                key_data,
            })
            .await?;

        self.installation_setting.refresh_value().await?;
        Ok(installation_state)
    }
}

fn normalize_required(value: &str, field: &'static str) -> Result<String, AppError> {
    let value = value.trim();
    if value.is_empty() {
        let code = match field {
            "username" => InstallErrorCode::UsernameRequired,
            "email" => InstallErrorCode::EmailRequired,
            "password" => InstallErrorCode::PasswordRequired,
            "domain" => InstallErrorCode::DomainRequired,
            _ => InstallErrorCode::UsernameRequired,
        };
        return Err(AppError::from_code(code));
    }

    Ok(value.to_owned())
}

fn normalize_domain(domain: &str) -> Result<String, AppError> {
    let domain = normalize_required(domain, "domain")?.to_lowercase();
    // If the domain contains a scheme (e.g. "https://localhost:5150"), skip
    // the dot-presence check since it is a full URL rather than a bare hostname.
    let is_url = domain.contains("://");
    if domain.contains(' ') || (!is_url && !domain.contains('.')) {
        return Err(AppError::from_code(InstallErrorCode::DomainInvalid));
    }

    Ok(domain)
}

fn normalize_email(email: &str) -> Result<String, AppError> {
    identity_domain::user::normalization::normalize_email(email).map_err(|error| match error {
        identity_domain::user::normalization::EmailNormalizationError::Empty => {
            AppError::from_code(InstallErrorCode::EmailRequired)
        }
        identity_domain::user::normalization::EmailNormalizationError::InvalidFormat
        | identity_domain::user::normalization::EmailNormalizationError::InvalidDomain => {
            AppError::from_code(InstallErrorCode::EmailInvalid)
        }
    })
}
