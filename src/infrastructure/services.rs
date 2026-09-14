use std::sync::Arc;

use sea_orm::DatabaseConnection;

use crate::config::{ClientCredentialRotationConfig, LoginWorkloadConfig};
use crate::{
    auth::{
        otp::TotpVerifierImpl, password::PasswordHasherImpl,
        workload::build_login_workload_authenticator,
    },
    crypto::{
        certificate_generator::CertificateGeneratorImpl,
        data_protection::XChaCha20DataProtectionCipher, key::AsymmetricKeyGeneratorImpl,
        key_jwk::KeyJwkGeneratorImpl, signing_algorithm::SigningAlgorithmDetectorImpl,
    },
    database::repository::{
        client_authorization::ClientAuthorizationRepositoryImpl,
        device_authorization::DeviceAuthorizationRepositoryImpl, install::InstallRepositoryImpl,
        key::KeyRepositoryImpl, key_jwk::KeyJwkRepositoryImpl, login::LoginRepositoryImpl,
        login_runtime::LoginRuntimeRepositoryImpl,
        openid_connect::OpenIdConnectClientRepositoryImpl,
        openid_connect_credential::OpenIdConnectCredentialRepositoryImpl,
        session::SessionRepositoryImpl, setting::SettingRepositoryImpl, user::UserRepositoryImpl,
        user_credential::UserCredentialRepositoryImpl,
    },
};
use identity_application::observability::EventSink;
use identity_application::{
    auth::{
        account::AccountService, login::LoginService, mfa::MfaService, session::SessionService,
    },
    data_protection::{DataProtector, DataProtectorImpl},
    install::InstallService,
    key::asymmetric::AsymmetricKeyService,
    openid_connect::{
        authorize::{AuthorizeService, AuthorizeServiceDependencies},
        client_authentication::{ClientAuthenticator, ClientAuthenticatorDependencies},
        device::{DeviceAuthorizationService, DeviceAuthorizationServiceDependencies},
        login_runtime::LoginRuntimeService,
        logout::{LogoutService, LogoutServiceDependencies},
        provider::OpenIdProviderService,
        registration::DynamicClientRegistrationService,
        remote::{backchannel_logout_http_client, request_uri_http_client},
        token::{TokenService, TokenServiceDependencies},
        user_info::UserInfoService,
    },
};
use identity_domain::openid_connect::{
    LoginRotationPolicy, OpenIdConnectClientRegistrationRepository, OpenIdConnectClientRepository,
    OpenIdConnectCredentialRepository, WorkloadAuthenticator,
};

use super::settings::AppRuntimeSettings;

pub type AppLoginService = LoginService;

pub type AppSessionService = SessionService;

pub type AppAccountService = AccountService;

pub type AppMfaService = MfaService;

pub type AppKeyService = AsymmetricKeyService;

pub type AppInstallService = InstallService<SettingRepositoryImpl>;

pub type AppOpenIdProviderService = OpenIdProviderService;

pub type AppOpenIdAuthorizeService = AuthorizeService;

pub type AppOpenIdTokenService = TokenService;

pub type AppOpenIdLogoutService = LogoutService;

pub type AppOpenIdUserInfoService = UserInfoService;

pub type AppDynamicClientRegistrationService = DynamicClientRegistrationService;

pub type AppDeviceAuthorizationService = DeviceAuthorizationService;
pub struct AppServices {
    login: AppLoginService,
    account: AppAccountService,
    session: AppSessionService,
    mfa: AppMfaService,
    key: AppKeyService,
    install: AppInstallService,
    oidc: AppOpenIdProviderService,
    oidc_authorize: AppOpenIdAuthorizeService,
    oidc_token: AppOpenIdTokenService,
    oidc_logout: AppOpenIdLogoutService,
    user_info: AppOpenIdUserInfoService,
    dynamic_client_registration: AppDynamicClientRegistrationService,
    device_authorization: AppDeviceAuthorizationService,
    login_runtime: LoginRuntimeService,
    workload_authenticator: Arc<dyn WorkloadAuthenticator>,
    oidc_client_repo: Arc<dyn OpenIdConnectClientRepository>,
    oidc_credential_repo: Arc<dyn OpenIdConnectCredentialRepository>,
    data_protector: Arc<dyn DataProtector>,
    events: Arc<dyn EventSink>,
}

impl AppServices {
    pub fn from_db(
        db: DatabaseConnection,
        settings: &AppRuntimeSettings,
    ) -> Result<Self, reqwest::Error> {
        Self::from_db_with_rotation(db, settings, &ClientCredentialRotationConfig::default())
    }

    pub fn from_db_with_rotation(
        db: DatabaseConnection,
        settings: &AppRuntimeSettings,
        rotation_config: &ClientCredentialRotationConfig,
    ) -> Result<Self, reqwest::Error> {
        Self::from_db_with_workload_auth(
            db,
            settings,
            rotation_config,
            build_login_workload_authenticator(&LoginWorkloadConfig::default())
                .expect("default login workload authenticator must build"),
        )
    }

    pub fn from_db_with_workload_auth(
        db: DatabaseConnection,
        settings: &AppRuntimeSettings,
        rotation_config: &ClientCredentialRotationConfig,
        workload_authenticator: Arc<dyn WorkloadAuthenticator>,
    ) -> Result<Self, reqwest::Error> {
        let request_uri_http_client = request_uri_http_client()?;
        let backchannel_logout_http_client = backchannel_logout_http_client()?;
        let key_repo = Arc::new(KeyRepositoryImpl::new(db.clone()));
        let signing_algorithm_detector = Arc::new(SigningAlgorithmDetectorImpl);
        let key_jwk_generator = Arc::new(KeyJwkGeneratorImpl);
        let data_protector = Arc::new(DataProtectorImpl::new(
            settings.key_ring(),
            Arc::new(XChaCha20DataProtectionCipher),
        ));
        let oidc_client_repo = Arc::new(OpenIdConnectClientRepositoryImpl::new(db.clone()));
        let oidc_client_registration_repo: Arc<dyn OpenIdConnectClientRegistrationRepository> =
            Arc::new(OpenIdConnectClientRepositoryImpl::new(db.clone()));
        let oidc_credential_repo = Arc::new(OpenIdConnectCredentialRepositoryImpl::new(db.clone()));
        let user_credential_repo = Arc::new(UserCredentialRepositoryImpl::new(db.clone()));
        let totp = Arc::new(TotpVerifierImpl);

        let events = crate::observability::events::sink();

        Ok(Self {
            login: LoginService::new(
                Arc::new(UserRepositoryImpl::new(db.clone())),
                user_credential_repo.clone(),
                Arc::new(SessionRepositoryImpl::new(db.clone())),
                Arc::new(LoginRepositoryImpl::new(db.clone())),
                Arc::new(PasswordHasherImpl::new()),
                totp.clone(),
                settings.password_hash_options(),
            )
            .with_device_repository(Arc::new(DeviceAuthorizationRepositoryImpl::new(db.clone())))
            .with_events(Arc::clone(&events)),
            session: SessionService::new(Arc::new(SessionRepositoryImpl::new(db.clone())))
                .with_events(Arc::clone(&events)),
            account: AccountService::new(Arc::new(UserRepositoryImpl::new(db.clone())))
                .with_events(Arc::clone(&events)),
            mfa: MfaService::new(
                user_credential_repo,
                totp.clone(),
                totp,
                data_protector.clone(),
            )
            .with_events(Arc::clone(&events)),
            key: AsymmetricKeyService::new(
                key_repo.clone(),
                Arc::new(AsymmetricKeyGeneratorImpl),
                key_jwk_generator.clone(),
                Some(Arc::new(KeyJwkRepositoryImpl::new(db.clone()))),
            )
            .with_runtime_key_ring(settings.key_ring()),
            install: InstallService {
                password_hasher: Arc::new(PasswordHasherImpl::new()),
                password_hash_options: settings.password_hash_options(),
                installation_initialized: settings.installation_initialized(),
                domain: settings.domain(),
                login_domain: settings.login_domain(),
                installation_first_user_oid: settings.installation_first_user_oid(),
                installation_first_key_oid: settings.installation_first_key_oid(),
                installation_initialized_at: settings.installation_initialized_at(),
                key_generator: Arc::new(AsymmetricKeyGeneratorImpl),
                certificate_generator: Arc::new(CertificateGeneratorImpl),
                repository: Arc::new(InstallRepositoryImpl::new(db.clone())),
                runtime_key_ring: settings.key_ring(),
                client_secret_lifetime: chrono::Duration::days(
                    rotation_config.credential_lifetime_days,
                ),
            },
            oidc: OpenIdProviderService::new(settings.installation())
                .with_dynamic_registration_setting(settings.dynamic_client_registration())
                .with_key_repo(key_repo.clone())
                .with_signing_algorithm_detector(signing_algorithm_detector.clone()),
            oidc_authorize: AuthorizeService::new(AuthorizeServiceDependencies {
                client_repo: oidc_client_repo.clone(),
                credential_repo: oidc_credential_repo.clone(),
                client_authorization_repo: Arc::new(ClientAuthorizationRepositoryImpl::new(
                    db.clone(),
                )),
                login_repo: Arc::new(LoginRepositoryImpl::new(db.clone())),
                user_repo: Arc::new(UserRepositoryImpl::new(db.clone())),
                key_repo: Arc::new(KeyRepositoryImpl::new(db.clone())),
                key_jwk_repo: Arc::new(KeyJwkRepositoryImpl::new(db.clone())),
                provider_service: Arc::new(OpenIdProviderService::new(settings.installation())),
                signing_algorithm_detector: signing_algorithm_detector.clone(),
                data_protector: data_protector.clone(),
                http_client: request_uri_http_client.clone(),
            })
            .with_events(Arc::clone(&events)),
            oidc_token: TokenService::new(TokenServiceDependencies {
                client_authorization_repo: Arc::new(ClientAuthorizationRepositoryImpl::new(
                    db.clone(),
                )),
                device_repo: Arc::new(DeviceAuthorizationRepositoryImpl::new(db.clone())),
                key_repo: Arc::new(KeyRepositoryImpl::new(db.clone())),
                key_jwk_repo: Arc::new(KeyJwkRepositoryImpl::new(db.clone())),
                user_repo: Arc::new(UserRepositoryImpl::new(db.clone())),
                client_repo: oidc_client_repo.clone(),
                credential_repo: oidc_credential_repo.clone(),
                provider_service: Arc::new(OpenIdProviderService::new(settings.installation())),
                signing_algorithm_detector: signing_algorithm_detector.clone(),
                data_protector: data_protector.clone(),
            })
            .with_runtime_key_ring(settings.key_ring())
            .with_session_repo(Arc::new(SessionRepositoryImpl::new(db.clone())))
            .with_events(Arc::clone(&events)),
            oidc_logout: LogoutService::new(LogoutServiceDependencies {
                client_repo: oidc_client_repo.clone(),
                provider_service: Arc::new(OpenIdProviderService::new(settings.installation())),
                key_repo: Arc::new(KeyRepositoryImpl::new(db.clone())),
                key_jwk_repo: Arc::new(KeyJwkRepositoryImpl::new(db.clone())),
                signing_algorithm_detector: signing_algorithm_detector.clone(),
                http_client: backchannel_logout_http_client,
            })
            .with_events(Arc::clone(&events)),
            user_info: UserInfoService::new(
                Arc::new(UserRepositoryImpl::new(db.clone())),
                oidc_client_repo.clone(),
                oidc_credential_repo.clone(),
                Arc::new(ClientAuthorizationRepositoryImpl::new(db.clone())),
                Arc::new(
                    AsymmetricKeyService::new(
                        Arc::new(KeyRepositoryImpl::new(db.clone())),
                        Arc::new(AsymmetricKeyGeneratorImpl),
                        key_jwk_generator,
                        Some(Arc::new(KeyJwkRepositoryImpl::new(db.clone()))),
                    )
                    .with_runtime_key_ring(settings.key_ring()),
                ),
                Arc::new(OpenIdProviderService::new(settings.installation())),
            )
            .with_device_repository(Arc::new(DeviceAuthorizationRepositoryImpl::new(db.clone()))),
            dynamic_client_registration: DynamicClientRegistrationService::new(
                settings.dynamic_client_registration(),
                oidc_client_registration_repo.clone(),
            )
            .with_events(Arc::clone(&events)),
            device_authorization: DeviceAuthorizationService::new(
                DeviceAuthorizationServiceDependencies {
                    login_domain: settings.login_domain(),
                    client_authentication: Arc::new(ClientAuthenticator::new(
                        ClientAuthenticatorDependencies {
                            client_repo: oidc_client_repo.clone(),
                            credential_repo: oidc_credential_repo.clone(),
                            provider_service: Arc::new(OpenIdProviderService::new(
                                settings.installation(),
                            )),
                        },
                    )),
                    client_repo: oidc_client_repo.clone(),
                    device_repo: Arc::new(DeviceAuthorizationRepositoryImpl::new(db.clone())),
                    provider_service: Arc::new(OpenIdProviderService::new(settings.installation())),
                    settings: settings.device_authorization(),
                },
            )
            .with_events(Arc::clone(&events)),
            login_runtime: LoginRuntimeService::new(
                Arc::new(LoginRuntimeRepositoryImpl::new(db.clone())),
                LoginRotationPolicy {
                    credential_lifetime: chrono::Duration::days(
                        rotation_config.credential_lifetime_days,
                    ),
                    rotate_before_expiry: chrono::Duration::days(
                        rotation_config.rotate_before_expiry_days,
                    ),
                    retire_after: chrono::Duration::seconds(rotation_config.retire_after_secs),
                },
                rotation_config.check_interval_secs.max(1),
            ),
            workload_authenticator,
            oidc_client_repo,
            oidc_credential_repo,
            data_protector,
            events,
        })
    }

    #[must_use]
    pub fn login(&self) -> &AppLoginService {
        &self.login
    }

    #[must_use]
    pub fn session(&self) -> &AppSessionService {
        &self.session
    }

    #[must_use]
    pub fn account(&self) -> &AppAccountService {
        &self.account
    }

    /// Key event and audit sink. Business use cases should receive this sink
    /// at construction; the accessor exists for adapters that must emit an
    /// audit fact at the boundary.
    #[must_use]
    pub fn events(&self) -> &Arc<dyn EventSink> {
        &self.events
    }

    #[must_use]
    pub fn mfa(&self) -> &AppMfaService {
        &self.mfa
    }

    #[must_use]
    pub fn key(&self) -> &AppKeyService {
        &self.key
    }

    #[must_use]
    pub fn install(&self) -> &AppInstallService {
        &self.install
    }

    #[must_use]
    pub fn oidc(&self) -> &AppOpenIdProviderService {
        &self.oidc
    }

    #[must_use]
    pub fn oidc_authorize(&self) -> &AppOpenIdAuthorizeService {
        &self.oidc_authorize
    }

    #[must_use]
    pub fn oidc_token(&self) -> &AppOpenIdTokenService {
        &self.oidc_token
    }

    #[must_use]
    pub fn oidc_logout(&self) -> &AppOpenIdLogoutService {
        &self.oidc_logout
    }

    #[must_use]
    pub fn user_info(&self) -> &AppOpenIdUserInfoService {
        &self.user_info
    }

    #[must_use]
    pub fn dynamic_client_registration(&self) -> &AppDynamicClientRegistrationService {
        &self.dynamic_client_registration
    }

    #[must_use]
    pub fn oidc_device_authorization(&self) -> &AppDeviceAuthorizationService {
        &self.device_authorization
    }

    #[must_use]
    pub fn login_runtime(&self) -> &LoginRuntimeService {
        &self.login_runtime
    }

    #[must_use]
    pub fn workload_authenticator(&self) -> &Arc<dyn WorkloadAuthenticator> {
        &self.workload_authenticator
    }

    #[must_use]
    pub fn oidc_client_repo(&self) -> &Arc<dyn OpenIdConnectClientRepository> {
        &self.oidc_client_repo
    }

    #[must_use]
    pub fn oidc_credential_repo(&self) -> &Arc<dyn OpenIdConnectCredentialRepository> {
        &self.oidc_credential_repo
    }

    #[must_use]
    pub fn data_protector(&self) -> &Arc<dyn DataProtector> {
        &self.data_protector
    }
}
