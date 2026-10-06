use http::{HeaderMap, StatusCode};
use identity_application::error::{
    AppError,
    codes::{authorize::AuthorizeErrorCode, authorize_http::AuthorizeHttpErrorCode},
};
use identity_domain::{
    auth::{SessionOid, model::ActiveSession},
    client_authorization::{ConsentState, StoredAuthorizationRequest},
    openid_connect::{OpenIdConnectClient, ScopeSet},
};
use identity_infrastructure::AppState;
use salvo::{Depot, Request, handler, handler::HoopedHandler};
use serde::Deserialize;
use url::Url;

use super::{
    super::{
        device::{device_consent_api, device_consent_submit, device_login_consent_api},
        pipeline::{Endpoint, Extract, RequireState, take},
    },
    interaction::{load_active_interaction, load_selected_sessions},
};
use crate::{
    controllers::{
        response::{AppResponse, WebError, WebResult, app_state, json_response},
        shared::{csrf_token, protocol_continue_uri},
    },
    views::oauth2::{
        ConsentApiResponse, ConsentDecision, ConsentDecisionPayload, ConsentPageData,
        build_scope_display,
    },
};

/// Identifies the interaction the consent UI is answering: a browser
/// authorization request (`login_id`) or a device request (`user_code`).
#[derive(Debug, Deserialize)]
struct ConsentQuery {
    login_id: Option<String>,
    user_code: Option<String>,
}

impl ConsentQuery {
    /// `Some(user_code)` for a device interaction, `None` for a browser
    /// authorization request. Anything else (both identifiers or neither) is
    /// rejected: the interaction must be unambiguous.
    fn device_target(&self) -> Result<Option<&str>, AppError> {
        match (self.login_id.as_deref(), self.user_code.as_deref()) {
            (Some(_), None) => Ok(None),
            (None, Some(user_code)) => Ok(Some(user_code)),
            _ => Err(AppError::from_code(
                AuthorizeHttpErrorCode::ContinueInteractionUnavailable,
            )),
        }
    }
}

pub fn get_endpoint() -> HoopedHandler {
    Endpoint::new("consent")
        .action("state", RequireState::<WebError>::new())
        .action("parse_query", Extract::<ConsentQuery, WebError>::query())
        .finish("load_consent", consent_get)
}

pub fn post_endpoint() -> HoopedHandler {
    Endpoint::new("consent_submit")
        .action("state", RequireState::<WebError>::new())
        .action(
            "parse_decision",
            Extract::<ConsentDecisionPayload, WebError>::json(),
        )
        .finish("submit_decision", consent_post)
}

#[handler]
async fn consent_get(depot: &mut Depot, req: &mut Request) -> WebResult {
    let ctx = app_state(depot)?;
    let query: ConsentQuery = take(depot)?;
    let headers: HeaderMap = req.headers().clone();

    if let Some(user_code) = query.device_target()? {
        return Ok(device_consent_api(&ctx, depot, user_code).await?.into());
    }
    let login_id = query.login_id.clone().unwrap_or_default();
    let login = ctx
        .services()
        .oidc_authorize()
        .load_login_by_protected_id(&login_id)
        .await?;
    if ctx
        .services()
        .oidc_device_authorization()
        .login_request(&login)
        .await?
        .is_some()
    {
        return Ok(
            device_login_consent_api(&ctx, &headers, depot, &login_id, &login)
                .await?
                .into(),
        );
    }

    let loaded = load_consent_context(&ctx, &login_id).await?;

    if loaded.stored.interaction.consent_state != ConsentState::Pending {
        return Err(
            AppError::from_code(AuthorizeHttpErrorCode::ContinueInteractionUnavailable).into(),
        );
    }

    let session = loaded
        .active_sessions
        .iter()
        .find(|session| Some(session.session_oid) == loaded.selected_session_oid)
        .ok_or_else(|| AppError::from_code(AuthorizeHttpErrorCode::ConsentSessionNotFound))?;
    let previously_granted = ctx
        .services()
        .oidc_authorize()
        .user_consented_scope_names(session.user_oid, loaded.client.client().oid)
        .await?;

    Ok(json_response(
        StatusCode::OK,
        ConsentPageData {
            login_id,
            client_name: loaded.client.client().name.clone(),
            logo_uri: loaded
                .client
                .metadata()
                .logo_uri
                .as_ref()
                .map(Url::to_string),
            client_uri: loaded
                .client
                .metadata()
                .client_uri
                .as_ref()
                .map(Url::to_string),
            scopes: build_scope_display(
                &loaded.scope,
                &previously_granted,
                &ctx.services()
                    .oidc_authorize()
                    .scope_descriptions(&loaded.scope)
                    .await?,
            ),
            csrf_token: csrf_token(depot),
            ui_locales: loaded.stored.request.ui_locales.clone(),
        },
    )
    .into())
}

#[handler]
async fn consent_post(depot: &mut Depot, req: &mut Request) -> WebResult {
    let ctx = app_state(depot)?;
    let headers: HeaderMap = req.headers().clone();
    let payload: ConsentDecisionPayload = take(depot)?;

    match (payload.login_id.as_deref(), payload.user_code.as_deref()) {
        (Some(login_id), None) => {
            let login = ctx
                .services()
                .oidc_authorize()
                .load_login_by_protected_id(login_id)
                .await?;
            if ctx
                .services()
                .oidc_device_authorization()
                .login_request(&login)
                .await?
                .is_some()
            {
                return Ok(
                    device_consent_submit(&ctx, &headers, &login, payload.decision)
                        .await?
                        .into(),
                );
            }
            Ok(handle_consent_decision(ctx, login_id.to_owned(), payload.decision).await?)
        }
        _ => {
            Err(AppError::from_code(AuthorizeHttpErrorCode::ContinueInteractionUnavailable).into())
        }
    }
}

pub(super) async fn handle_consent_decision(
    ctx: AppState,
    login_id: String,
    decision: ConsentDecision,
) -> Result<AppResponse, AppError> {
    let loaded = load_consent_context(&ctx, &login_id).await?;

    if loaded.stored.interaction.consent_state != ConsentState::Pending {
        return Err(AppError::from_code(
            AuthorizeHttpErrorCode::ContinueInteractionUnavailable,
        ));
    }

    if !has_selected_session(loaded.selected_session_oid, &loaded.active_sessions) {
        return Err(AppError::from_code(
            AuthorizeHttpErrorCode::ConsentSessionNotFound,
        ));
    }

    let consent_state = match decision {
        ConsentDecision::Approve => ConsentState::Approved,
        ConsentDecision::Deny => ConsentState::Denied,
    };
    ctx.services()
        .oidc_authorize()
        .record_consent_by_login(&login_id, consent_state)
        .await?;

    Ok(json_response(
        StatusCode::OK,
        ConsentApiResponse {
            status: match decision {
                ConsentDecision::Approve => "approved",
                ConsentDecision::Deny => "denied",
            },
            continue_uri: Some(loaded.continue_uri),
            error: None,
        },
    )
    .into())
}

struct LoadedConsentContext {
    stored: StoredAuthorizationRequest,
    client: OpenIdConnectClient,
    scope: ScopeSet,
    selected_session_oid: Option<SessionOid>,
    active_sessions: Vec<ActiveSession>,
    continue_uri: String,
}

async fn load_consent_context(
    ctx: &AppState,
    login_id: &str,
) -> Result<LoadedConsentContext, AppError> {
    let continue_context = load_active_interaction(ctx, login_id).await?;

    let scope = ScopeSet::parse(&continue_context.stored.request.scope)
        .map_err(AppError::map_source(AuthorizeErrorCode::ScopeInvalid))?;
    let selected_session_oid = continue_context.login.session_oid;
    let active_sessions = load_selected_sessions(ctx, selected_session_oid).await?;

    Ok(LoadedConsentContext {
        continue_uri: protocol_continue_uri(ctx, login_id)?,
        stored: continue_context.stored,
        client: continue_context.client,
        scope,
        selected_session_oid,
        active_sessions,
    })
}

fn has_selected_session(
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
