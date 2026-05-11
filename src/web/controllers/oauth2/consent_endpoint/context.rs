use http::HeaderMap;

use crate::{
    application::error::{AppError, codes::authorize_http::AuthorizeHttpErrorCode},
    boot::AppState,
    domain::{
        auth::model::ActiveSession, auth::SessionOid,
        client_authorization::StoredAuthorizationRequest,
        openid_connect::OpenIdConnectClient,
    },
    web::controllers::shared::load_active_sessions,
};

pub(super) struct LoadedConsentContext {
    pub(super) stored: StoredAuthorizationRequest,
    pub(super) client: OpenIdConnectClient,
    pub(super) active_sessions: Vec<ActiveSession>,
    pub(super) continue_uri: String,
}

pub(super) async fn load_consent_context(
    ctx: &AppState,
    headers: &HeaderMap,
    login_id: &str,
) -> Result<LoadedConsentContext, AppError> {
    let active_sessions = load_active_sessions(ctx, headers).await?;
    let continue_context = ctx
        .services()
        .oidc_authorize()
        .load_continue_context_by_login(login_id)
        .await?;

    if continue_context.expires_at <= chrono::Utc::now() || continue_context.completed_at.is_some()
    {
        return Err(AppError::from_code(
            AuthorizeHttpErrorCode::ContinueInteractionUnavailable,
        ));
    }

    Ok(LoadedConsentContext {
        continue_uri: format!(
            "/oauth2/continue?login_id={}",
            urlencoding::encode(login_id)
        ),
        stored: continue_context.stored,
        client: continue_context.client,
        active_sessions,
    })
}

pub(super) fn has_selected_session(
    selected_session_oid: Option<SessionOid>,
    active_sessions: &[ActiveSession],
) -> bool {
    selected_session_oid
        .and_then(|selected_session_oid| {
            active_sessions
                .iter()
                .find(|session| session.session_oid == selected_session_oid)
        })
        .is_some()
}
