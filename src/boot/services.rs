use std::sync::Arc;

use sea_orm::DatabaseConnection;

use crate::application::{
    auth::{login::LoginService, session::SessionService},
    install::InstallService,
    key::asymmetric::AsymmetricKeyService,
};
use crate::infrastructure::{
    auth::{otp::TotpVerifierImpl, password::PasswordHasherImpl},
    crypto::key::AsymmetricKeyGeneratorImpl,
    database::repository::{
        key::KeyRepositoryImpl, login::LoginRepositoryImpl, session::SessionRepositoryImpl,
        user::UserRepositoryImpl, user_credential::UserCredentialRepositoryImpl,
    },
};

use super::settings::AppRuntimeSettings;

pub type AppLoginService = LoginService;

pub type AppSessionService = SessionService;

pub type AppKeyService = AsymmetricKeyService;

pub type AppInstallService = InstallService;

pub struct AppServices {
    login: AppLoginService,
    session: AppSessionService,
    key: AppKeyService,
    install: AppInstallService,
}

impl AppServices {
    #[must_use]
    pub fn from_db(db: DatabaseConnection, settings: &AppRuntimeSettings) -> Self {
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
                repo: Arc::new(KeyRepositoryImpl::new(db.clone())),
                generator: Arc::new(AsymmetricKeyGeneratorImpl),
            },
            install: InstallService {
                db,
                password_hasher: Arc::new(PasswordHasherImpl::new()),
                password_hash_options: settings.password_hash_options(),
                installation_setting: settings.installation(),
                key_generator: Arc::new(AsymmetricKeyGeneratorImpl),
            },
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
}
