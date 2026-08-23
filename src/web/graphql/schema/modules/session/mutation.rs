use async_graphql::{Context, Error, ID, Object, Result};
use identity_domain::{auth::SessionOid, openid_connect::ApiScope};
use identity_infrastructure::{
    database::repository::session::SessionRepositoryImpl, graphql::id::GlobalId,
};
use uuid::Uuid;

use super::{
    SessionGlobalId,
    types::{RevokeOtherSessionsPayload, RevokeSessionPayload, SessionNode},
};
use crate::graphql::schema::{
    authorization::{request_context, require_scope},
    error::internal_error,
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
            .session_repo
            .find_by_oid(SessionOid(oid))
            .await
            .map_err(internal_error)?
            .ok_or_else(|| Error::new("session not found"))?;
        if session.user_oid != Uuid::from(request.claims.user_oid) {
            return Err(Error::new("session not found"));
        }
        let session = request
            .state
            .services()
            .session()
            .revoke(session.oid)
            .await
            .map_err(internal_error)?;
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
        let repo = SessionRepositoryImpl::new(request.state.resources().db().clone());
        let sessions = repo
            .list_by_user_oid(Uuid::from(request.claims.user_oid))
            .await
            .map_err(internal_error)?;
        let mut revoked_count = 0;
        for session in sessions
            .into_iter()
            .filter(|session| session.oid != request.claims.session_oid)
            .filter(|session| session.status == identity_domain::auth::SessionStatus::ACTIVE)
            .filter(|session| session.revoked_at.is_none())
        {
            request
                .state
                .services()
                .session()
                .revoke(session.oid)
                .await
                .map_err(internal_error)?;
            revoked_count += 1;
        }
        Ok(RevokeOtherSessionsPayload::new(
            revoked_count,
            client_mutation_id,
        ))
    }
}
