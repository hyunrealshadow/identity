use crate::auth::password::run_password_hashing;
use crate::key::runtime::RuntimeKeyRingProvider;
use crate::observability::BusinessEvent;
use crate::observability::EventValue;
use crate::observability::error_outcome;
use crate::observability::event_sink;
use chrono::Duration;
use identity_domain::key::AsymmetricKeyData;
use identity_domain::key::generator::AsymmetricKeySpec;
use identity_domain::user::normalization::EmailNormalizationError;
use identity_domain::user::normalization::normalize_email as normalization_normalize_email;
use std::sync::Arc;

use async_trait::async_trait;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::Utc;
use rand::RngExt;
use url::Url;
use uuid::Uuid;

use crate::{
    application::{
        error::{
            AppError,
            codes::{common::CommonErrorCode, install::InstallErrorCode},
        },
        setting::{PasswordHashSetting, SettingsSource, runtime::RefreshableSetting},
    },
    auth::password::PasswordHasher,
    domain::key::{
        AsymmetricKeyAlgorithm, algorithm::JwaSigningAlgorithm, generator::AsymmetricKeyGenerator,
    },
    setting::{
        DomainSetting, InstallationSettings, LoginClientIdSetting, LoginDomainSetting,
        SettingChanges,
    },
    user::model::Password,
};

#[derive(Debug, Clone)]
pub struct InstallInput {
    pub username: String,
    pub email: String,
    pub password: String,
    pub domain: String,
    pub application_url: String,
    /// Wire name of the signing algorithm, e.g. `ecdsa-p256`.
    pub key_algorithm: String,
}

pub trait InstallSettings: SettingsSource + RefreshableSetting {}

impl<T> InstallSettings for T where T: SettingsSource + RefreshableSetting + ?Sized {}

pub struct InstallService {
    pub password_hasher: Arc<dyn PasswordHasher>,
    pub settings: Arc<dyn InstallSettings>,
    pub key_generator: Arc<dyn AsymmetricKeyGenerator>,
    pub certificate_generator: Arc<dyn CertificateGenerator>,
    pub repository: Arc<dyn InstallRepository>,
    pub runtime_key_ring: Arc<dyn RuntimeKeyRingProvider>,
    pub client_secret_lifetime: Duration,
}

pub trait CertificateGenerator: Send + Sync {
    fn generate_self_signed(
        &self,
        private_key_pem: &str,
        domain: &str,
        algorithm: &AsymmetricKeyAlgorithm,
    ) -> Result<String, AppError>;
}

/// Everything the storage layer needs to record a fresh installation.
#[derive(Debug, Clone)]
pub struct InstallationData {
    pub username: String,
    pub email: String,
    pub password: Password,
    pub user_oid: Uuid,
    pub application_url: Url,
    pub client_id: Uuid,
    pub client_secret: String,
    pub client_secret_lifetime: Duration,
    pub key_oid: Uuid,
    pub key_data: AsymmetricKeyData,
    /// The installation settings, written in the same transaction.
    pub settings: SettingChanges,
}

/// Storage port for a complete installation. The implementation writes the
/// first user, its credential, the signing key, the built-in client and the
/// installation settings as one atomic unit.
#[async_trait]
pub trait InstallRepository: Send + Sync {
    async fn create_installation(&self, data: InstallationData) -> Result<(), AppError>;
}

impl InstallService {
    pub fn is_initialized(&self) -> bool {
        self.settings
            .snapshot()
            .section::<InstallationSettings>()
            .initialized
    }

    #[tracing::instrument(skip_all, name = "install")]
    pub async fn install(&self, input: InstallInput) -> Result<(), AppError> {
        let result = self.install_inner(input).await;

        let event = match &result {
            Ok(()) => BusinessEvent::audit("install.result")
                .outcome("success")
                .attribute("stage", EventValue::Text("completed".to_owned())),
            Err(error) => {
                let (outcome, reason) = error_outcome(error);
                BusinessEvent::audit("install.result")
                    .outcome(outcome)
                    .reason(reason)
                    .attribute("error_code", EventValue::Integer(i64::from(error.code())))
            }
        };
        event_sink().emit(event);
        result
    }

    async fn install_inner(&self, input: InstallInput) -> Result<(), AppError> {
        if self.is_initialized() {
            return Err(AppError::from_code(InstallErrorCode::AlreadyInitialized));
        }

        let input = validate_install_input(input)?;

        let hash_options = self.settings.snapshot().get::<PasswordHashSetting>();
        let password_hasher = Arc::clone(&self.password_hasher);
        let password =
            run_password_hashing(move || password_hasher.hash(&input.password, &hash_options))
                .await?;
        let mut key_data = self.key_generator.generate(&AsymmetricKeySpec {
            algorithm: input.key_algorithm.clone(),
        })?;
        let certificate = self.certificate_generator.generate_self_signed(
            &key_data.private_key,
            &input.domain,
            &input.key_algorithm,
        )?;
        key_data.certificate = Some(certificate);
        let client_id = Uuid::new_v4();
        let mut client_secret_bytes = [0_u8; 32];
        rand::rng().fill(&mut client_secret_bytes);
        let client_secret = URL_SAFE_NO_PAD.encode(client_secret_bytes);
        let user_oid = Uuid::new_v4();
        let key_oid = Uuid::new_v4();
        let settings = SettingChanges::default()
            .set::<DomainSetting>(&Some(input.domain))?
            .set::<LoginDomainSetting>(&login_app_domain(&input.application_url))?
            .set::<LoginClientIdSetting>(&Some(client_id))?
            .set_section(&InstallationSettings {
                initialized: true,
                initialized_at: Some(Utc::now()),
            })?;

        self.repository
            .create_installation(InstallationData {
                username: input.username,
                email: input.email,
                password,
                user_oid,
                application_url: input.application_url,
                client_id,
                client_secret: client_secret.clone(),
                client_secret_lifetime: self.client_secret_lifetime,
                key_oid,
                key_data,
                settings,
            })
            .await?;

        self.settings.refresh_value().await?;
        self.runtime_key_ring.refresh_value().await?;

        Ok(())
    }
}

#[derive(Debug)]
struct ValidatedInstallInput {
    username: String,
    email: String,
    password: String,
    domain: String,
    application_url: Url,
    key_algorithm: AsymmetricKeyAlgorithm,
}

fn validate_install_input(input: InstallInput) -> Result<ValidatedInstallInput, AppError> {
    let mut validation = AppError::from_code(CommonErrorCode::ValidationFailed);
    let username = collect_field(
        &mut validation,
        "username",
        normalize_required(&input.username, "username"),
    );
    let email = collect_field(&mut validation, "email", normalize_email(&input.email));
    let password = collect_field(
        &mut validation,
        "password",
        normalize_required(&input.password, "password"),
    );
    let domain = collect_field(&mut validation, "domain", normalize_domain(&input.domain));
    let application_url = collect_field(
        &mut validation,
        "application_url",
        normalize_application_url(&input.application_url),
    );
    let key_algorithm = collect_field(
        &mut validation,
        "key_algorithm",
        parse_install_key_algorithm(&input.key_algorithm),
    );
    if validation
        .validation()
        .is_some_and(|details| !details.is_empty())
    {
        return Err(validation);
    }

    Ok(ValidatedInstallInput {
        username: username.expect("validated username"),
        email: email.expect("validated email"),
        password: password.expect("validated password"),
        domain: domain.expect("validated domain"),
        application_url: application_url.expect("validated application URL"),
        key_algorithm: key_algorithm.expect("validated key algorithm"),
    })
}

fn normalize_application_url(value: &str) -> Result<Url, AppError> {
    let mut url = Url::parse(value.trim())
        .map_err(|_| AppError::from_code(InstallErrorCode::ApplicationUrlInvalid))?;
    if url.scheme() != "https"
        || url.host_str().is_none()
        || url.path() != "/"
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err(AppError::from_code(InstallErrorCode::ApplicationUrlInvalid));
    }
    url.set_path("");
    Ok(url)
}

fn collect_field<T>(
    validation: &mut AppError,
    field: &'static str,
    result: Result<T, AppError>,
) -> Option<T> {
    match result {
        Ok(value) => Some(value),
        Err(error) => {
            validation.push_field_error(field, error);
            None
        }
    }
}

fn normalize_required(value: &str, field: &'static str) -> Result<String, AppError> {
    let value = value.trim();
    if value.is_empty() {
        let code = match field {
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
    normalization_normalize_email(email).map_err(|error| match error {
        EmailNormalizationError::Empty => AppError::from_code(InstallErrorCode::EmailRequired),
        EmailNormalizationError::InvalidFormat | EmailNormalizationError::InvalidDomain => {
            AppError::from_code(InstallErrorCode::EmailInvalid)
        }
    })
}

/// Origin of the login application, e.g. `https://login.example.com`.
///
/// Only http(s) URLs have a usable origin; anything else leaves the setting
/// empty and lets the configuration stay authoritative.
fn login_app_domain(application_url: &Url) -> Option<String> {
    matches!(application_url.scheme(), "http" | "https")
        .then(|| application_url.origin().ascii_serialization())
}

/// Parses the algorithm a client asked for and rejects the ones this
/// installation cannot sign with.
fn parse_install_key_algorithm(value: &str) -> Result<AsymmetricKeyAlgorithm, AppError> {
    let unsupported = || {
        AppError::from_code(InstallErrorCode::UnsupportedAlgorithm).with_param("algorithm", value)
    };
    let algorithm: AsymmetricKeyAlgorithm = value.parse().map_err(|_| unsupported())?;
    algorithm.validate().map_err(|_| unsupported())?;
    if JwaSigningAlgorithm::trials_for_key_type(&algorithm).is_empty() {
        return Err(unsupported());
    }

    Ok(algorithm)
}

#[cfg(test)]
mod tests {
    use crate::domain::key::ALL_ASYMMETRIC_KEY_ALGORITHMS;
    use crate::domain::key::AsymmetricKeyAlgorithm;

    use super::{InstallInput, validate_install_input};
    use crate::application::error::code::AppErrorCode;
    use crate::application::error::codes::common::CommonErrorCode;

    #[test]
    fn install_validation_rejects_an_unknown_algorithm_name() {
        let error = validate_install_input(install_input("rsa-1024"))
            .expect_err("an unknown algorithm name should fail validation");

        assert_eq!(error.code(), CommonErrorCode::ValidationFailed.code());
        let details = error.validation().expect("validation details");
        assert_eq!(
            details
                .fields()
                .iter()
                .map(|field| (field.field(), field.code()))
                .collect::<Vec<_>>(),
            vec![("key_algorithm", 13009)]
        );
        assert_eq!(
            details.fields()[0].params().get("algorithm"),
            Some("rsa-1024")
        );
    }

    #[test]
    fn install_validation_rejects_an_algorithm_that_cannot_sign() {
        let error = validate_install_input(install_input("x25519"))
            .expect_err("a key agreement algorithm cannot be the signing key");

        let details = error.validation().expect("validation details");
        assert_eq!(
            details
                .fields()
                .iter()
                .map(|field| (field.field(), field.code()))
                .collect::<Vec<_>>(),
            vec![("key_algorithm", 13009)]
        );
    }

    #[test]
    fn install_validation_accepts_every_offered_name() {
        for algorithm in ALL_ASYMMETRIC_KEY_ALGORITHMS.iter().filter(|algorithm| {
            !matches!(
                algorithm,
                AsymmetricKeyAlgorithm::X25519 | AsymmetricKeyAlgorithm::X448
            )
        }) {
            validate_install_input(install_input(&algorithm.to_string()))
                .unwrap_or_else(|error| panic!("{algorithm} should be accepted: {error}"));
        }
    }

    fn install_input(key_algorithm: &str) -> InstallInput {
        InstallInput {
            username: "admin".to_owned(),
            email: "admin@example.com".to_owned(),
            password: "correct horse battery staple".to_owned(),
            domain: "identity.example.com".to_owned(),
            application_url: "https://login.example.com".to_owned(),
            key_algorithm: key_algorithm.to_owned(),
        }
    }

    #[test]
    fn install_validation_collects_all_invalid_fields() {
        let error = validate_install_input(InstallInput {
            username: " ".to_owned(),
            email: "not-an-email".to_owned(),
            password: String::new(),
            domain: "invalid domain".to_owned(),
            application_url: "not-a-url".to_owned(),
            key_algorithm: "ecdsa-p256".to_owned(),
        })
        .expect_err("invalid form should fail validation");

        assert_eq!(error.code(), CommonErrorCode::ValidationFailed.code());
        let fields = error
            .validation()
            .expect("validation details should be attached")
            .fields();
        assert_eq!(fields.len(), 5);
        assert_eq!(
            fields
                .iter()
                .map(|field| (field.field(), field.code()))
                .collect::<Vec<_>>(),
            vec![
                ("username", 13001),
                ("email", 13006),
                ("password", 13003),
                ("domain", 13005),
                ("application_url", 13010),
            ]
        );
    }
}
