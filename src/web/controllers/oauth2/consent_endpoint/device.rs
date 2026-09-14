//! Device branch of the shared consent interaction (RFC 8628 §3.3).
//!
//! The consent UI renders both flows: an authorization request is addressed by
//! `login_id`, a device request by `user_code`. Nothing else differs from the
//! UI's point of view — the same CSRF token, the same display fields, and a
//! decision response without a continue URI, because a device approval never
//! redirects to the client.

use http::{HeaderMap, StatusCode};
use salvo::Depot;

use crate::{
    application::{
        error::{AppError, codes::device::DeviceAuthorizationErrorCode},
        openid_connect::device::{DeviceVerificationDecision, DeviceVerificationUser},
    },
    boot::AppState,
    domain::{auth::model::ActiveSession, openid_connect::ScopeSet},
    web::{
        controllers::shared::{csrf_token, load_active_sessions},
        views::oauth2::{
            ConsentApiResponse, ConsentDecision, DeviceConsentPageData, build_scope_display,
        },
    },
};

/// Describes a device request for the consent UI.
pub(super) async fn device_consent_api(
    ctx: &AppState,
    headers: &HeaderMap,
    depot: &Depot,
    user_code: &str,
) -> Result<salvo::Response, AppError> {
    // The browser must still be authenticated, but the lookup itself stays
    // read-only: approving happens only through the CSRF protected POST.
    verification_actor(ctx, headers).await?;
    let description = ctx
        .services()
        .oidc_device_authorization()
        .describe_verification(user_code)
        .await?;
    let scope = ScopeSet::parse(&description.scopes.join(" ")).unwrap_or_default();

    Ok(crate::web::controllers::response::json_response(
        StatusCode::OK,
        DeviceConsentPageData {
            user_code: description.user_code,
            status: description.status,
            consent_required: description.consent_required,
            client_name: description.client_name,
            logo_uri: description.logo_uri,
            client_uri: description.client_uri,
            scopes: build_scope_display(&scope),
            csrf_token: csrf_token(depot),
        },
    ))
}

/// Records the decision of an authenticated browser on a device request.
pub(super) async fn device_consent_submit(
    ctx: &AppState,
    headers: &HeaderMap,
    user_code: &str,
    decision: ConsentDecision,
) -> Result<salvo::Response, AppError> {
    let actor = verification_actor(ctx, headers).await?;
    let decision = match decision {
        ConsentDecision::Approve => DeviceVerificationDecision::Approve,
        ConsentDecision::Deny => DeviceVerificationDecision::Deny,
    };
    ctx.services()
        .oidc_device_authorization()
        .decide_verification(user_code, &actor.user(), decision)
        .await?;

    Ok(crate::web::controllers::response::json_response(
        StatusCode::OK,
        ConsentApiResponse {
            status: match decision {
                DeviceVerificationDecision::Approve => "approved",
                DeviceVerificationDecision::Deny => "denied",
            },
            // A device decision is complete in itself: the client learns the
            // result by polling, never through a browser redirect.
            continue_uri: None,
            error: None,
        },
    ))
}

/// The browser session answering the request.
struct VerificationActor {
    session: ActiveSession,
}

impl VerificationActor {
    fn user(&self) -> DeviceVerificationUser {
        DeviceVerificationUser {
            user_oid: self.session.user_oid,
            auth_time: Some(self.session.authenticated_at.timestamp()),
            acr: self.session.acr.clone(),
            amr: self.session.amr.clone(),
        }
    }
}

async fn verification_actor(
    ctx: &AppState,
    headers: &HeaderMap,
) -> Result<VerificationActor, AppError> {
    // The verification page runs in the login application, so the session
    // arrives through the login transport (`x-sessions`), exactly like the
    // other interactions it drives.
    let sessions = load_active_sessions(ctx, headers).await?;
    let session = sessions.into_iter().next().ok_or_else(|| {
        AppError::from_code(DeviceAuthorizationErrorCode::VerificationLoginRequired)
    })?;

    Ok(VerificationActor { session })
}
