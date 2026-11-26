use std::collections::HashMap;

use chrono::Utc;
use identity_application::{error::codes::authorize, openid_connect::authorize::ContinueContext};
use identity_domain::auth::SessionOid;

pub(crate) use crate::application::openid_connect::authorize::FlowDecision;
use crate::{
    application::{error::AppError, openid_connect::authorize::AuthorizeService},
    domain::{auth::model::ActiveSession, openid_connect::AuthorizationRequest},
    infrastructure::AppState,
};

pub(super) async fn determine_authorize_flow(
    request: &AuthorizationRequest,
    sessions: &[ActiveSession],
    protected_session_ids: &HashMap<SessionOid, String>,
    login_id: String,
    authorize_service: &AuthorizeService,
) -> Result<FlowDecision, AppError> {
    authorize_service
        .determine_authorize_flow(request, sessions, protected_session_ids, login_id)
        .await
}

pub(super) async fn load_active_interaction(
    ctx: &AppState,
    login_id: &str,
) -> Result<ContinueContext, AppError> {
    let continue_context = ctx
        .services()
        .oidc_authorize()
        .load_continue_context_by_login(login_id)
        .await?;
    if continue_context.expires_at <= Utc::now() || continue_context.completed_at.is_some() {
        return Err(authorize::error::InteractionUnavailable.into());
    }
    Ok(continue_context)
}

pub(super) async fn load_selected_sessions(
    ctx: &AppState,
    selected_session_oid: Option<SessionOid>,
) -> Result<Vec<ActiveSession>, AppError> {
    match selected_session_oid {
        Some(session_oid) => {
            ctx.services()
                .session()
                .get_active_accounts(&[session_oid])
                .await
        }
        None => Ok(Vec::new()),
    }
}
