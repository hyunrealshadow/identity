use async_graphql::{Error, ErrorExtensions, Result};
use identity_application::error::{code::AppErrorCode, codes::graphql::GraphqlErrorCode};
use identity_application::openid_connect::user_info::PrincipalClaims;
use identity_domain::user::User;
use identity_domain::{client_authorization::AccessTokenPrincipal, user::UserOid};
use identity_infrastructure::AppState;
use unic_langid::LanguageIdentifier;

use crate::middleware::RequestCorrelation;

pub struct RequestContext {
    pub state: AppState,
    pub claims: PrincipalClaims,
    pub user: Option<User>,
    pub locale: LanguageIdentifier,
    /// Request/trace correlation generated at the HTTP boundary. It is copied
    /// into GraphQL response and field-error extensions by the transport and by
    /// the schema error helpers.
    pub correlation: RequestCorrelation,
    pub actor: identity_domain::authorization::ActorContext,
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
                Error::new(self.state.resources().i18n().t_code(
                    &self.locale,
                    GraphqlErrorCode::UserAuthenticationRequired.code(),
                ))
                .extend_with(|_, extensions| {
                    extensions.set("code", GraphqlErrorCode::UserAuthenticationRequired.code());
                    extensions.set("kind", "forbidden");
                    extensions.set("requestId", self.correlation.request_id.clone());
                    if let Some(trace_id) = &self.correlation.trace_id {
                        extensions.set("traceId", trace_id.clone());
                    }
                })
            })
    }

    pub fn user_oid(&self) -> Result<UserOid> {
        Ok(self.user()?.oid)
    }
}
