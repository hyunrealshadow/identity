use async_graphql::Result;
use identity_application::{error::codes::graphql, openid_connect::user_info::PrincipalClaims};
use identity_domain::{
    authorization::ActorContext,
    client_authorization::AccessTokenPrincipal,
    user::{User, UserOid},
};
use identity_infrastructure::AppState;
use unic_langid::LanguageIdentifier;

use super::error::project;

pub struct RequestContext {
    pub state: AppState,
    pub claims: PrincipalClaims,
    pub user: Option<User>,
    pub locale: LanguageIdentifier,
    pub actor: ActorContext,
}

impl RequestContext {
    pub fn user(&self) -> Result<&User> {
        self.user
            .as_ref()
            .filter(|user| {
                self.claims.principal == AccessTokenPrincipal::User
                    && self.claims.user_oid == Some(user.oid)
            })
            .ok_or_else(|| {
                project(
                    self.state.resources().i18n(),
                    &self.locale,
                    &graphql::error::UserAuthenticationRequired.into_error(),
                )
            })
    }

    pub fn user_oid(&self) -> Result<UserOid> {
        Ok(self.user()?.oid)
    }
}
