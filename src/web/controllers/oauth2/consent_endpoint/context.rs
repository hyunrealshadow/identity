use crate::{
    application::error::{
        AppError,
        codes::{authorize::AuthorizeErrorCode, authorize_http::AuthorizeHttpErrorCode},
    },
    boot::AppState,
    domain::{
        auth::SessionOid,
        auth::model::ActiveSession,
        client_authorization::StoredAuthorizationRequest,
        openid_connect::{OpenIdConnectClient, ScopeSet},
    },
    web::controllers::shared::protocol_continue_uri,
};

pub(super) struct LoadedConsentContext {
    pub(super) stored: StoredAuthorizationRequest,
    pub(super) client: OpenIdConnectClient,
    pub(super) scope: ScopeSet,
    pub(super) selected_session_oid: Option<SessionOid>,
    pub(super) active_sessions: Vec<ActiveSession>,
    pub(super) continue_uri: String,
}

pub(super) async fn load_consent_context(
    ctx: &AppState,
    login_id: &str,
) -> Result<LoadedConsentContext, AppError> {
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

    let scope = ScopeSet::parse(&continue_context.stored.request.scope).map_err(|error| {
        AppError::from_code(AuthorizeErrorCode::ScopeInvalid).with_source(error)
    })?;
    let selected_session_oid = continue_context.login.session_oid;
    let active_sessions = match selected_session_oid {
        Some(session_oid) => {
            ctx.services()
                .session()
                .get_active_accounts(&[session_oid])
                .await?
        }
        None => Vec::new(),
    };

    Ok(LoadedConsentContext {
        continue_uri: protocol_continue_uri(ctx, login_id)?,
        stored: continue_context.stored,
        client: continue_context.client,
        scope,
        selected_session_oid,
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
