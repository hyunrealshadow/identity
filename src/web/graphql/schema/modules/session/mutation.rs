use crate::graphql::schema::access::access;
use async_graphql::{Context, ID, Object, Result};
use identity_application::error::{codes::graphql::GraphqlErrorCode, params::ErrorParams};
use identity_domain::{auth::SessionOid, openid_connect::ApiScope};
use identity_infrastructure::graphql::id::GlobalId;
use tracing::warn;
use uuid::Uuid;

use super::{
    SessionGlobalId,
    types::{RevokeOtherSessionsPayload, RevokeSessionPayload, SessionNode},
};
use crate::graphql::schema::{
    authorization::{ScopeGuard, UserPrincipalGuard, request_context},
    error::{app_error, coded_error, internal_error},
};

#[derive(Default)]
pub(crate) struct SessionMutation;

#[Object]
impl SessionMutation {
    #[graphql(guard = "UserPrincipalGuard.and(ScopeGuard::new(ApiScope::SessionRevoke))",
        directive = access::apply(ScopeGuard::policy(ApiScope::SessionRevoke)))]
    async fn revoke_session(
        &self,
        ctx: &Context<'_>,
        id: ID,
        #[graphql(validator(chars_max_length = 255))] client_mutation_id: Option<String>,
    ) -> Result<RevokeSessionPayload> {
        let request = request_context(ctx)?;
        let oid = GlobalId::<SessionGlobalId>::try_from(&id)
            .map_err(|_| coded_error(ctx, GraphqlErrorCode::InvalidSessionId, ErrorParams::new()))?
            .oid();
        let session = request
            .state
            .services()
            .session()
            .revoke_for_user(SessionOid(oid), Uuid::from(request.user_oid()?))
            .await
            .map_err(|error| app_error(ctx, error))?;
        Ok(RevokeSessionPayload::new(
            SessionNode::new(session, request.claims.session_oid),
            client_mutation_id,
        ))
    }

    #[graphql(guard = "UserPrincipalGuard.and(ScopeGuard::new(ApiScope::SessionRevoke))",
        directive = access::apply(ScopeGuard::policy(ApiScope::SessionRevoke)))]
    async fn revoke_other_sessions(
        &self,
        ctx: &Context<'_>,
        #[graphql(validator(chars_max_length = 255))] client_mutation_id: Option<String>,
    ) -> Result<RevokeOtherSessionsPayload> {
        let request = request_context(ctx)?;
        let session_oid = request.claims.session_oid.ok_or_else(|| {
            coded_error(
                ctx,
                GraphqlErrorCode::BrowserSessionRequired,
                ErrorParams::new(),
            )
        })?;
        let outcome = request
            .state
            .services()
            .session()
            .revoke_other_sessions(Uuid::from(request.user_oid()?), session_oid)
            .await
            .map_err(|error| internal_error(ctx, error))?;
        if outcome.has_failures() {
            warn!(
                target: "identity.graphql",
                failed = outcome.failure_count(),
                "session revocation batch partially failed"
            );
        }
        Ok(RevokeOtherSessionsPayload::new(
            outcome.revoked as i32,
            client_mutation_id,
        ))
    }
}
