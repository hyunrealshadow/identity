use std::sync::Arc;

use sea_orm::DatabaseConnection;

use crate::application::{
    auth::{login::LoginService, session::SessionService},
    data_protection::{DataProtector, DataProtectorImpl},
    install::InstallService,
    key::asymmetric::AsymmetricKeyService,
    openid_connect::{
        authorize::AuthorizeService, provider::OpenIdProviderService, token::TokenService,
        user_info::UserInfoService,
    },
};
use crate::infrastructure::{
    auth::{otp::TotpVerifierImpl, password::PasswordHasherImpl},
    crypto::key::AsymmetricKeyGeneratorImpl,
    database::repository::{
        client_authorization::ClientAuthorizationRepositoryImpl, key::KeyRepositoryImpl,
        key_jwk::KeyJwkRepositoryImpl, login::LoginRepositoryImpl,
        openid_connect::OpenIdConnectClientRepositoryImpl,
        openid_connect_credential::OpenIdConnectCredentialRepositoryImpl,
        session::SessionRepositoryImpl, user::UserRepositoryImpl,
        user_credential::UserCredentialRepositoryImpl,
    },
};

use super::settings::AppRuntimeSettings;

pub type AppLoginService = LoginService;

pub type AppSessionService = SessionService;

pub type AppKeyService = AsymmetricKeyService;

pub type AppInstallService = InstallService;

pub type AppOpenIdProviderService = OpenIdProviderService;

pub type AppOpenIdAuthorizeService = AuthorizeService;

pub type AppOpenIdTokenService = TokenService;

pub type AppOpenIdUserInfoService = UserInfoService;

pub struct AppServices {
    login: AppLoginService,
    session: AppSessionService,
    key: AppKeyService,
    install: AppInstallService,
    oidc: AppOpenIdProviderService,
    oidc_authorize: AppOpenIdAuthorizeService,
    oidc_token: AppOpenIdTokenService,
    user_info: AppOpenIdUserInfoService,
    data_protector: Arc<dyn DataProtector>,
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
}

impl AppServices {
    #[must_use]
    pub fn from_db(db: DatabaseConnection, settings: &AppRuntimeSettings) -> Self {
        let key_repo = Arc::new(KeyRepositoryImpl::new(db.clone()));
        let data_protector = Arc::new(DataProtectorImpl::new(key_repo.clone()));

        Self {
            login: LoginService {
                user_repo: Arc::new(UserRepositoryImpl::new(db.clone())),
                credential_repo: Arc::new(UserCredentialRepositoryImpl::new(db.clone())),
                session_repo: Arc::new(SessionRepositoryImpl::new(db.clone())),
                login_repo: Arc::new(LoginRepositoryImpl::new(db.clone())),
                password_hasher: Arc::new(PasswordHasherImpl::new()),
                totp_verifier: Arc::new(TotpVerifierImpl),
                hash_options: settings.password_hash_options(),
            },
            session: SessionService {
                session_repo: Arc::new(SessionRepositoryImpl::new(db.clone())),
            },
            key: AsymmetricKeyService {
                repo: key_repo.clone(),
                generator: Arc::new(AsymmetricKeyGeneratorImpl),
                jwk_repo: Some(Arc::new(KeyJwkRepositoryImpl::new(db.clone()))),
            },
            install: InstallService {
                db: db.clone(),
                password_hasher: Arc::new(PasswordHasherImpl::new()),
                password_hash_options: settings.password_hash_options(),
                installation_setting: settings.installation(),
                key_generator: Arc::new(AsymmetricKeyGeneratorImpl),
            },
            oidc: OpenIdProviderService::new(settings.installation())
                .with_key_repo(key_repo.clone()),
            oidc_authorize: AuthorizeService::new(
                Arc::new(OpenIdConnectClientRepositoryImpl::new(db.clone())),
                Arc::new(OpenIdConnectCredentialRepositoryImpl::new(db.clone())),
                Arc::new(ClientAuthorizationRepositoryImpl::new(db.clone())),
                Arc::new(LoginRepositoryImpl::new(db.clone())),
                Arc::new(OpenIdProviderService::new(settings.installation())),
                data_protector.clone(),
            ),
            oidc_token: TokenService::new(
                Arc::new(ClientAuthorizationRepositoryImpl::new(db.clone())),
                Arc::new(KeyRepositoryImpl::new(db.clone())),
                Arc::new(UserRepositoryImpl::new(db.clone())),
                Arc::new(OpenIdConnectClientRepositoryImpl::new(db.clone())),
                Arc::new(OpenIdConnectCredentialRepositoryImpl::new(db.clone())),
                Arc::new(OpenIdProviderService::new(settings.installation())),
                data_protector.clone(),
            ),
            user_info: UserInfoService::new(
                Arc::new(UserRepositoryImpl::new(db.clone())),
                Arc::new(ClientAuthorizationRepositoryImpl::new(db.clone())),
                Arc::new(AsymmetricKeyService {
                    repo: Arc::new(KeyRepositoryImpl::new(db.clone())),
                    generator: Arc::new(AsymmetricKeyGeneratorImpl),
                    jwk_repo: None,
                }),
                Arc::new(OpenIdProviderService::new(settings.installation())),
            ),
            data_protector,
        }
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
    pub fn user_info(&self) -> &AppOpenIdUserInfoService {
        &self.user_info
    }

    #[must_use]
    pub fn data_protector(&self) -> &Arc<dyn DataProtector> {
        &self.data_protector
    }
}
