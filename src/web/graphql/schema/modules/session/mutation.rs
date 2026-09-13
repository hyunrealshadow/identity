use async_graphql::{Context, Error, ID, Object, Result};
use identity_domain::{auth::SessionOid, openid_connect::ApiScope};
use identity_infrastructure::graphql::id::GlobalId;

use super::{
    SessionGlobalId,
    types::{RevokeOtherSessionsPayload, RevokeSessionPayload, SessionNode},
};
use crate::graphql::schema::{
    authorization::{request_context, require_scope},
    error::{app_error, internal_error},
};

#[derive(Default)]
pub(crate) struct SessionMutation;

#[Object]
impl SessionMutation {
    async fn revoke_session(
        &self,
        ctx: &Context<'_>,
        id: ID,
        client_mutation_id: Option<String>,
    ) -> Result<RevokeSessionPayload> {
        require_scope(ctx, ApiScope::SessionRevoke)?;
        let request = request_context(ctx)?;
        let oid = GlobalId::<SessionGlobalId>::try_from(&id)
            .map_err(|_| Error::new("invalid session id"))?
            .oid();
        let session = request
            .state
            .services()
            .session()
            .revoke_for_user(SessionOid(oid), uuid::Uuid::from(request.claims.user_oid))
            .await
            .map_err(|error| app_error(ctx, error))?;
        Ok(RevokeSessionPayload::new(
            SessionNode::new(session, request.claims.session_oid),
            client_mutation_id,
        ))
    }

    async fn revoke_other_sessions(
        &self,
        ctx: &Context<'_>,
        client_mutation_id: Option<String>,
    ) -> Result<RevokeOtherSessionsPayload> {
        require_scope(ctx, ApiScope::SessionRevoke)?;
        let request = request_context(ctx)?;
        let outcome = request
            .state
            .services()
            .session()
            .revoke_other_sessions(
                uuid::Uuid::from(request.claims.user_oid),
                request.claims.session_oid.ok_or_else(|| {
                    Error::new("this token was not issued from a browser session")
                })?,
            )
            .await
            .map_err(internal_error)?;
        if outcome.has_failures() {
            tracing::warn!(
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
