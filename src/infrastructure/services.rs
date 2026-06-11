use std::sync::Arc;

use sea_orm::DatabaseConnection;

use crate::{
    auth::{otp::TotpVerifierImpl, password::PasswordHasherImpl},
    crypto::{
        certificate_generator::CertificateGeneratorImpl,
        data_protection::XChaCha20DataProtectionCipher, key::AsymmetricKeyGeneratorImpl,
        key_jwk::KeyJwkGeneratorImpl, signing_algorithm::SigningAlgorithmDetectorImpl,
    },
    database::repository::{
        client_authorization::ClientAuthorizationRepositoryImpl, install::InstallPersistenceImpl,
        key::KeyRepositoryImpl, key_jwk::KeyJwkRepositoryImpl, login::LoginRepositoryImpl,
        openid_connect::OpenIdConnectClientRepositoryImpl,
        openid_connect_credential::OpenIdConnectCredentialRepositoryImpl,
        session::SessionRepositoryImpl, setting::SettingRepositoryImpl, user::UserRepositoryImpl,
        user_credential::UserCredentialRepositoryImpl,
    },
};
use identity_application::{
    auth::{login::LoginService, session::SessionService},
    data_protection::{DataProtector, DataProtectorImpl},
    install::InstallService,
    key::asymmetric::AsymmetricKeyService,
    openid_connect::{
        authorize::{AuthorizeService, AuthorizeServiceDependencies},
        logout::{LogoutService, LogoutServiceDependencies},
        provider::OpenIdProviderService,
        registration::DynamicClientRegistrationService,
        remote::{backchannel_logout_http_client, request_uri_http_client},
        token::{TokenService, TokenServiceDependencies},
        user_info::UserInfoService,
    },
};
use identity_domain::openid_connect::{
    OpenIdConnectClientRegistrationRepository, OpenIdConnectClientRepository,
    OpenIdConnectCredentialRepository,
};

use super::settings::AppRuntimeSettings;

pub type AppLoginService = LoginService;

pub type AppSessionService = SessionService;

pub type AppKeyService = AsymmetricKeyService;

pub type AppInstallService = InstallService<SettingRepositoryImpl>;

pub type AppOpenIdProviderService = OpenIdProviderService;

pub type AppOpenIdAuthorizeService = AuthorizeService;

pub type AppOpenIdTokenService = TokenService;

pub type AppOpenIdLogoutService = LogoutService;

pub type AppOpenIdUserInfoService = UserInfoService;

pub type AppDynamicClientRegistrationService = DynamicClientRegistrationService;

pub struct AppServices {
    login: AppLoginService,
    session: AppSessionService,
    key: AppKeyService,
    install: AppInstallService,
    oidc: AppOpenIdProviderService,
    oidc_authorize: AppOpenIdAuthorizeService,
    oidc_token: AppOpenIdTokenService,
    oidc_logout: AppOpenIdLogoutService,
    user_info: AppOpenIdUserInfoService,
    dynamic_client_registration: AppDynamicClientRegistrationService,
    oidc_client_repo: Arc<dyn OpenIdConnectClientRepository>,
    oidc_credential_repo: Arc<dyn OpenIdConnectCredentialRepository>,
    data_protector: Arc<dyn DataProtector>,
}

impl AppServices {
    pub fn from_db(
        db: DatabaseConnection,
        settings: &AppRuntimeSettings,
    ) -> Result<Self, reqwest::Error> {
        let request_uri_http_client = request_uri_http_client()?;
        let backchannel_logout_http_client = backchannel_logout_http_client()?;
        let key_repo = Arc::new(KeyRepositoryImpl::new(db.clone()));
        let signing_algorithm_detector = Arc::new(SigningAlgorithmDetectorImpl);
        let key_jwk_generator = Arc::new(KeyJwkGeneratorImpl);
        let data_protector = Arc::new(DataProtectorImpl::new(
            key_repo.clone(),
            Arc::new(XChaCha20DataProtectionCipher),
        ));
        let oidc_client_repo = Arc::new(OpenIdConnectClientRepositoryImpl::new(db.clone()));
        let oidc_client_registration_repo: Arc<dyn OpenIdConnectClientRegistrationRepository> =
            Arc::new(OpenIdConnectClientRepositoryImpl::new(db.clone()));
        let oidc_credential_repo = Arc::new(OpenIdConnectCredentialRepositoryImpl::new(db.clone()));

        Ok(Self {
            login: LoginService::new(
                Arc::new(UserRepositoryImpl::new(db.clone())),
                Arc::new(UserCredentialRepositoryImpl::new(db.clone())),
                Arc::new(SessionRepositoryImpl::new(db.clone())),
                Arc::new(LoginRepositoryImpl::new(db.clone())),
                Arc::new(PasswordHasherImpl::new()),
                Arc::new(TotpVerifierImpl),
                settings.password_hash_options(),
            ),
            session: SessionService {
                session_repo: Arc::new(SessionRepositoryImpl::new(db.clone())),
            },
            key: AsymmetricKeyService::new(
                key_repo.clone(),
                Arc::new(AsymmetricKeyGeneratorImpl),
                key_jwk_generator.clone(),
                Some(Arc::new(KeyJwkRepositoryImpl::new(db.clone()))),
            ),
            install: InstallService {
                password_hasher: Arc::new(PasswordHasherImpl::new()),
                password_hash_options: settings.password_hash_options(),
                installation_initialized: settings.installation_initialized(),
                installation_domain: settings.installation_domain(),
                installation_first_user_oid: settings.installation_first_user_oid(),
                installation_first_key_oid: settings.installation_first_key_oid(),
                installation_initialized_at: settings.installation_initialized_at(),
                key_generator: Arc::new(AsymmetricKeyGeneratorImpl),
                certificate_generator: Arc::new(CertificateGeneratorImpl),
                persistence: Arc::new(InstallPersistenceImpl::new(db.clone())),
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
            }),
            oidc_token: TokenService::new(TokenServiceDependencies {
                client_authorization_repo: Arc::new(ClientAuthorizationRepositoryImpl::new(
                    db.clone(),
                )),
                key_repo: Arc::new(KeyRepositoryImpl::new(db.clone())),
                key_jwk_repo: Arc::new(KeyJwkRepositoryImpl::new(db.clone())),
                user_repo: Arc::new(UserRepositoryImpl::new(db.clone())),
                client_repo: oidc_client_repo.clone(),
                credential_repo: oidc_credential_repo.clone(),
                provider_service: Arc::new(OpenIdProviderService::new(settings.installation())),
                signing_algorithm_detector: signing_algorithm_detector.clone(),
                data_protector: data_protector.clone(),
            }),
            oidc_logout: LogoutService::new(LogoutServiceDependencies {
                client_repo: oidc_client_repo.clone(),
                provider_service: Arc::new(OpenIdProviderService::new(settings.installation())),
                key_repo: Arc::new(KeyRepositoryImpl::new(db.clone())),
                key_jwk_repo: Arc::new(KeyJwkRepositoryImpl::new(db.clone())),
                signing_algorithm_detector: signing_algorithm_detector.clone(),
                http_client: backchannel_logout_http_client,
            }),
            user_info: UserInfoService::new(
                Arc::new(UserRepositoryImpl::new(db.clone())),
                oidc_client_repo.clone(),
                oidc_credential_repo.clone(),
                Arc::new(ClientAuthorizationRepositoryImpl::new(db.clone())),
                Arc::new(AsymmetricKeyService::new(
                    Arc::new(KeyRepositoryImpl::new(db.clone())),
                    Arc::new(AsymmetricKeyGeneratorImpl),
                    key_jwk_generator,
                    Some(Arc::new(KeyJwkRepositoryImpl::new(db.clone()))),
                )),
                Arc::new(OpenIdProviderService::new(settings.installation())),
            ),
            dynamic_client_registration: DynamicClientRegistrationService::new(
                settings.dynamic_client_registration(),
                oidc_client_registration_repo.clone(),
            ),
            oidc_client_repo,
            oidc_credential_repo,
            data_protector,
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

#[cfg(test)]
mod tests {
    use super::AppServices;

    #[test]
    fn exposes_openid_connect_provider_service() {
        let _ = AppServices::oidc;
    }

    #[test]
    fn exposes_openid_connect_authorize_service() {
        let _ = AppServices::oidc_authorize;
    }

    #[test]
    fn exposes_openid_connect_token_service() {
        let _ = AppServices::oidc_token;
    }

    #[test]
    fn exposes_oidc_client_repo() {
        let _ = AppServices::oidc_client_repo;
    }

    #[test]
    fn exposes_oidc_credential_repo() {
        let _ = AppServices::oidc_credential_repo;
    }
}
