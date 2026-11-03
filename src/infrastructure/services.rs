use std::{error::Error as StdError, sync::Arc};

use identity_application::{
    auth::{
        account::AccountService, login::LoginService, mfa::MfaService, passkey::PasskeyService,
        session::SessionService,
    },
    console::ConsoleRuntimeService,
    data_protection::{DataProtector, DataProtectorImpl},
    install::InstallService,
    instance_overview::InstanceOverviewService,
    key::{asymmetric::AsymmetricKeyService, rotation::KeyRotationService},
    observability::EventSink,
    openid_connect::{
        authorize::{AuthorizeService, AuthorizeServiceDependencies},
        client_authentication::{ClientAuthenticator, ClientAuthenticatorDependencies},
        device::{DeviceAuthorizationService, DeviceAuthorizationServiceDependencies},
        login_runtime::LoginRuntimeService,
        logout::{LogoutService, LogoutServiceDependencies},
        par::PushedAuthorizationService,
        provider::OpenIdProviderService,
        registration::DynamicClientRegistrationService,
        remote::{conformance_allows_invalid_certs, request_uri_http_client},
        token::{TokenService, TokenServiceDependencies},
        user_info::UserInfoService,
    },
    rbac::{GroupManagementService, RbacManagementService},
    user::management::UserManagementService,
};
use identity_domain::{
    openid_connect::{
        BUILTIN_CLIENT_SECRET_LIFETIME, OpenIdConnectClientRegistrationRepository,
        OpenIdConnectClientRepository, OpenIdConnectCredentialRepository, WorkloadAuthenticator,
    },
    rbac::RbacAuthorizationRepository,
};
type Error = Box<dyn StdError + Send + Sync>;
use sea_orm::DatabaseConnection;

use super::settings::AppRuntimeSettings;
use crate::{
    auth::{
        breached_password::PwnedPasswordChecker, otp::TotpVerifierImpl,
        passkey::WebAuthnAuthenticator, password::PasswordHasherImpl,
        workload::build_workload_authenticator,
    },
    config::WorkloadsConfig,
    crypto::{
        certificate_generator::CertificateGeneratorImpl,
        data_protection::XChaCha20DataProtectionCipher, key::AsymmetricKeyGeneratorImpl,
        key_jwk::KeyJwkGeneratorImpl, key_rotation::KeyRotationMaterialGeneratorImpl,
        signing_algorithm::SigningAlgorithmDetectorImpl,
    },
    database::{
        repository::{
            authorization::AuthorizationRepositoryImpl, challenge::ChallengeRepositoryImpl,
            client_authorization::ClientAuthorizationRepositoryImpl,
            device_authorization::DeviceAuthorizationRepositoryImpl,
            group_management::GroupManagementRepositoryImpl, install::InstallRepositoryImpl,
            instance_overview::InstanceOverviewRepositoryImpl, key::KeyRepositoryImpl,
            key_jwk::KeyJwkRepositoryImpl, key_rotation::KeyRotationRepositoryImpl,
            login::LoginRepositoryImpl, login_runtime::LoginRuntimeRepositoryImpl,
            oauth_resource::OAuthResourceRepositoryImpl,
            openid_connect::OpenIdConnectClientRepositoryImpl,
            openid_connect_credential::OpenIdConnectCredentialRepositoryImpl,
            rbac_authorization::RbacAuthorizationRepositoryImpl,
            rbac_management::RbacManagementRepositoryImpl,
            scope_catalog::ScopeCatalogRepositoryImpl, session::SessionRepositoryImpl,
            user::UserRepositoryImpl, user_credential::UserCredentialRepositoryImpl,
            user_management::UserManagementRepositoryImpl,
        },
        seed::console::ConsoleClientSeedConfig,
    },
    observability::events::sink,
    openid_connect::backchannel_logout::HttpBackChannelLogoutSender,
};

pub type AppLoginService = LoginService;

pub type AppSessionService = SessionService;

pub type AppAccountService = AccountService;

pub type AppMfaService = MfaService;

pub type AppKeyService = AsymmetricKeyService;

pub type AppInstallService = InstallService;

pub type AppOpenIdProviderService = OpenIdProviderService;

pub type AppOpenIdAuthorizeService = AuthorizeService;

pub type AppOpenIdTokenService = TokenService;

pub type AppOpenIdLogoutService = LogoutService;

pub type AppOpenIdUserInfoService = UserInfoService;

pub type AppDynamicClientRegistrationService = DynamicClientRegistrationService;

pub type AppDeviceAuthorizationService = DeviceAuthorizationService;
pub struct AppServices {
    authorization: Arc<AuthorizationRepositoryImpl>,
    login: AppLoginService,
    passkey: Arc<PasskeyService>,
    account: AppAccountService,
    session: AppSessionService,
    mfa: AppMfaService,
    key: AppKeyService,
    key_rotation: KeyRotationService,
    install: AppInstallService,
    instance_overview: InstanceOverviewService,
    user_management: UserManagementService,
    rbac_management: RbacManagementService,
    group_management: GroupManagementService,
    oidc: AppOpenIdProviderService,
    oidc_authorize: AppOpenIdAuthorizeService,
    pushed_authorization: PushedAuthorizationService,
    oidc_token: AppOpenIdTokenService,
    oidc_logout: AppOpenIdLogoutService,
    user_info: AppOpenIdUserInfoService,
    dynamic_client_registration: AppDynamicClientRegistrationService,
    device_authorization: AppDeviceAuthorizationService,
    login_runtime: LoginRuntimeService,
    console_runtime: ConsoleRuntimeService,
    workload_authenticator: Arc<dyn WorkloadAuthenticator>,
    oidc_client_repo: Arc<dyn OpenIdConnectClientRepository>,
    oidc_credential_repo: Arc<dyn OpenIdConnectCredentialRepository>,
    data_protector: Arc<dyn DataProtector>,
    events: Arc<dyn EventSink>,
}

impl AppServices {
    pub fn from_db(db: DatabaseConnection, settings: &AppRuntimeSettings) -> Result<Self, Error> {
        Self::from_db_with_workload_auth(
            db,
            settings,
            build_workload_authenticator(&WorkloadsConfig::default())
                .expect("default workload authenticator must build"),
        )
    }

    pub fn from_db_with_workload_auth(
        db: DatabaseConnection,
        settings: &AppRuntimeSettings,
        workload_authenticator: Arc<dyn WorkloadAuthenticator>,
    ) -> Result<Self, Error> {
        let request_uri_http_client = request_uri_http_client()?;
        let backchannel_sender = Arc::new(HttpBackChannelLogoutSender::new(
            conformance_allows_invalid_certs(),
        )?);
        let key_repo = Arc::new(KeyRepositoryImpl::new(db.clone()));
        let signing_algorithm_detector = Arc::new(SigningAlgorithmDetectorImpl);
        let key_jwk_generator = Arc::new(KeyJwkGeneratorImpl);
        let data_protector = Arc::new(DataProtectorImpl::new(
            settings.key_ring(),
            Arc::new(XChaCha20DataProtectionCipher),
        ));
        let scope_catalog = Arc::new(ScopeCatalogRepositoryImpl::new(db.clone()));
        let oidc_client_repo = Arc::new(OpenIdConnectClientRepositoryImpl::new(db.clone()));
        let oidc_client_registration_repo: Arc<dyn OpenIdConnectClientRegistrationRepository> =
            Arc::new(OpenIdConnectClientRepositoryImpl::new(db.clone()));
        let oauth_resource_repo = Arc::new(OAuthResourceRepositoryImpl::new(db.clone()));
        let oidc_credential_repo = Arc::new(OpenIdConnectCredentialRepositoryImpl::new(db.clone()));
        let user_credential_repo = Arc::new(UserCredentialRepositoryImpl::new(db.clone()));
        let totp = Arc::new(TotpVerifierImpl);

        let events = sink();
        let authorization = Arc::new(AuthorizationRepositoryImpl::new(db.clone()));
        let breach_checker = Arc::new(PwnedPasswordChecker::new()?);
        let passkey = Arc::new(
            PasskeyService::new(
                user_credential_repo.clone(),
                Arc::new(ChallengeRepositoryImpl::new(db.clone())),
                Arc::new(WebAuthnAuthenticator::new(settings.store())),
            )
            .with_events(Arc::clone(&events)),
        );

        let rbac_authorization_repo: Arc<dyn RbacAuthorizationRepository> =
            Arc::new(RbacAuthorizationRepositoryImpl::new(db.clone()));

        let client_authorization_repo =
            Arc::new(ClientAuthorizationRepositoryImpl::new(db.clone()));
        let oidc_authorize = AuthorizeService::new(AuthorizeServiceDependencies {
            client_repo: oidc_client_repo.clone(),
            credential_repo: oidc_credential_repo.clone(),
            client_authorization_repo: client_authorization_repo.clone(),
            login_repo: Arc::new(LoginRepositoryImpl::new(db.clone())),
            user_repo: Arc::new(UserRepositoryImpl::new(db.clone())),
            key_repo: Arc::new(KeyRepositoryImpl::new(db.clone())),
            key_jwk_repo: Arc::new(KeyJwkRepositoryImpl::new(db.clone())),
            provider_service: Arc::new(
                OpenIdProviderService::new(settings.store())
                    .with_scope_catalog(scope_catalog.clone())
                    .with_resource_repo(oauth_resource_repo.clone())
                    .with_rbac_authorization_repository(rbac_authorization_repo.clone()),
            ),
            signing_algorithm_detector: signing_algorithm_detector.clone(),
            data_protector: data_protector.clone(),
            http_client: request_uri_http_client.clone(),
        })
        .with_scope_catalog(Arc::new(ScopeCatalogRepositoryImpl::new(db.clone())))
        .with_session_repo(Arc::new(SessionRepositoryImpl::new(db.clone())))
        .with_management_authority_repository(authorization.clone())
        .with_rbac_authorization_repository(rbac_authorization_repo.clone())
        .with_events(Arc::clone(&events));
        Ok(Self {
            authorization: authorization.clone(),
            passkey: passkey.clone(),
            login: LoginService::new(
                Arc::new(UserRepositoryImpl::new(db.clone())),
                user_credential_repo.clone(),
                Arc::new(SessionRepositoryImpl::new(db.clone())),
                Arc::new(LoginRepositoryImpl::new(db.clone())),
                Arc::new(PasswordHasherImpl::new()),
                totp.clone(),
                settings.store(),
            )
            .with_breach_checker(breach_checker.clone())
            .with_passkeys(passkey)
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
            key_rotation: KeyRotationService::new(
                Arc::new(KeyRotationRepositoryImpl::new(db.clone())),
                Arc::new(KeyRotationMaterialGeneratorImpl),
                settings.key_ring(),
            ),
            install: InstallService {
                breach_checker: breach_checker.clone(),
                password_hasher: Arc::new(PasswordHasherImpl::new()),
                settings: settings.store(),
                key_generator: Arc::new(AsymmetricKeyGeneratorImpl),
                certificate_generator: Arc::new(CertificateGeneratorImpl),
                repository: Arc::new(InstallRepositoryImpl::new(db.clone())),
                runtime_key_ring: settings.key_ring(),
                client_secret_lifetime: BUILTIN_CLIENT_SECRET_LIFETIME,
            },
            instance_overview: InstanceOverviewService::new(Arc::new(
                InstanceOverviewRepositoryImpl::new(db.clone()),
            )),
            user_management: UserManagementService::new(
                Arc::new(UserManagementRepositoryImpl::new(db.clone())),
                Arc::new(PasswordHasherImpl::new()),
                breach_checker.clone(),
                settings.store(),
                data_protector.clone(),
            )
            .with_events(Arc::clone(&events)),
            rbac_management: RbacManagementService::new(
                Arc::new(RbacManagementRepositoryImpl::new(db.clone())),
                data_protector.clone(),
            )
            .with_events(Arc::clone(&events)),
            group_management: GroupManagementService::new(
                Arc::new(GroupManagementRepositoryImpl::new(db.clone())),
                data_protector.clone(),
            )
            .with_events(Arc::clone(&events)),
            oidc: OpenIdProviderService::new(settings.store())
                .with_scope_catalog(scope_catalog.clone())
                .with_resource_repo(oauth_resource_repo.clone())
                .with_rbac_authorization_repository(rbac_authorization_repo.clone())
                .with_key_repo(key_repo.clone())
                .with_key_jwk_repo(Arc::new(KeyJwkRepositoryImpl::new(db.clone())))
                .with_signing_algorithm_detector(signing_algorithm_detector.clone()),
            oidc_authorize: oidc_authorize.clone(),
            pushed_authorization: PushedAuthorizationService::new(
                Arc::new(ClientAuthenticator::new(ClientAuthenticatorDependencies {
                    client_repo: oidc_client_repo.clone(),
                    credential_repo: oidc_credential_repo.clone(),
                    provider_service: Arc::new(
                        OpenIdProviderService::new(settings.store())
                            .with_scope_catalog(scope_catalog.clone())
                            .with_resource_repo(oauth_resource_repo.clone())
                            .with_rbac_authorization_repository(rbac_authorization_repo.clone()),
                    ),
                })),
                oidc_authorize,
                client_authorization_repo,
                Arc::new(
                    OpenIdProviderService::new(settings.store())
                        .with_scope_catalog(scope_catalog.clone())
                        .with_resource_repo(oauth_resource_repo.clone())
                        .with_rbac_authorization_repository(rbac_authorization_repo.clone()),
                ),
            ),
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
                provider_service: Arc::new(
                    OpenIdProviderService::new(settings.store())
                        .with_scope_catalog(scope_catalog.clone())
                        .with_resource_repo(oauth_resource_repo.clone())
                        .with_rbac_authorization_repository(rbac_authorization_repo.clone()),
                ),
                signing_algorithm_detector: signing_algorithm_detector.clone(),
                data_protector: data_protector.clone(),
            })
            .with_runtime_key_ring(settings.key_ring())
            .with_session_repo(Arc::new(SessionRepositoryImpl::new(db.clone())))
            .with_management_authority_repository(authorization.clone())
            .with_rbac_authorization_repository(rbac_authorization_repo.clone())
            .with_events(Arc::clone(&events)),
            oidc_logout: LogoutService::new(LogoutServiceDependencies {
                client_repo: oidc_client_repo.clone(),
                provider_service: Arc::new(
                    OpenIdProviderService::new(settings.store())
                        .with_scope_catalog(scope_catalog.clone())
                        .with_resource_repo(oauth_resource_repo.clone())
                        .with_rbac_authorization_repository(rbac_authorization_repo.clone()),
                ),
                key_repo: Arc::new(KeyRepositoryImpl::new(db.clone())),
                key_jwk_repo: Arc::new(KeyJwkRepositoryImpl::new(db.clone())),
                signing_algorithm_detector: signing_algorithm_detector.clone(),
                backchannel_sender,
            })
            .with_session_repo(Arc::new(SessionRepositoryImpl::new(db.clone())))
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
                Arc::new(
                    OpenIdProviderService::new(settings.store())
                        .with_scope_catalog(scope_catalog.clone())
                        .with_resource_repo(oauth_resource_repo.clone())
                        .with_rbac_authorization_repository(rbac_authorization_repo.clone()),
                ),
            )
            .with_device_repository(Arc::new(DeviceAuthorizationRepositoryImpl::new(db.clone())))
            .with_session_repo(Arc::new(SessionRepositoryImpl::new(db.clone())))
            .with_management_authority_repository(authorization.clone())
            .with_rbac_authorization_repository(rbac_authorization_repo.clone()),
            dynamic_client_registration: DynamicClientRegistrationService::new(
                settings.store(),
                oidc_client_registration_repo.clone(),
            )
            .with_credential_repository(oidc_credential_repo.clone())
            .with_scope_catalog(scope_catalog.clone())
            .with_events(Arc::clone(&events)),
            device_authorization: DeviceAuthorizationService::new(
                DeviceAuthorizationServiceDependencies {
                    client_authentication: Arc::new(ClientAuthenticator::new(
                        ClientAuthenticatorDependencies {
                            client_repo: oidc_client_repo.clone(),
                            credential_repo: oidc_credential_repo.clone(),
                            provider_service: Arc::new(
                                OpenIdProviderService::new(settings.store())
                                    .with_scope_catalog(scope_catalog.clone())
                                    .with_resource_repo(oauth_resource_repo.clone())
                                    .with_rbac_authorization_repository(
                                        rbac_authorization_repo.clone(),
                                    ),
                            ),
                        },
                    )),
                    client_repo: oidc_client_repo.clone(),
                    device_repo: Arc::new(DeviceAuthorizationRepositoryImpl::new(db.clone())),
                    provider_service: Arc::new(
                        OpenIdProviderService::new(settings.store())
                            .with_scope_catalog(scope_catalog.clone())
                            .with_resource_repo(oauth_resource_repo.clone())
                            .with_rbac_authorization_repository(rbac_authorization_repo.clone()),
                    ),
                    settings: settings.store(),
                },
            )
            .with_events(Arc::clone(&events)),
            login_runtime: LoginRuntimeService::new(
                Arc::new(LoginRuntimeRepositoryImpl::new(db.clone())),
                settings.store(),
            ),
            console_runtime: ConsoleRuntimeService::new(settings.store()),
            workload_authenticator,
            oidc_client_repo,
            oidc_credential_repo,
            data_protector,
            events,
        })
    }

    #[must_use]
    pub fn passkey(&self) -> &PasskeyService {
        &self.passkey
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
    pub fn key_rotation(&self) -> &KeyRotationService {
        &self.key_rotation
    }

    #[must_use]
    pub fn install(&self) -> &AppInstallService {
        &self.install
    }

    #[must_use]
    pub fn instance_overview(&self) -> &InstanceOverviewService {
        &self.instance_overview
    }

    #[must_use]
    pub fn user_management(&self) -> &UserManagementService {
        &self.user_management
    }

    #[must_use]
    pub fn rbac_management(&self) -> &RbacManagementService {
        &self.rbac_management
    }

    #[must_use]
    pub fn group_management(&self) -> &GroupManagementService {
        &self.group_management
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
    pub fn pushed_authorization(&self) -> &PushedAuthorizationService {
        &self.pushed_authorization
    }

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
    pub fn console_runtime(&self) -> &ConsoleRuntimeService {
        &self.console_runtime
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

    #[must_use]
    pub fn authorization(&self) -> &Arc<AuthorizationRepositoryImpl> {
        &self.authorization
    }

    pub fn with_console_installation(
        mut self,
        db: DatabaseConnection,
        config: Option<ConsoleClientSeedConfig>,
    ) -> Self {
        self.install.repository =
            Arc::new(InstallRepositoryImpl::new(db).with_console_client_config(config));
        self
    }
}
