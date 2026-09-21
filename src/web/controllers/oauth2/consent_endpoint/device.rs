//! Device consent is addressed by the login bound when the user code is claimed.

use http::{HeaderMap, StatusCode};
use salvo::Depot;

use crate::{
    application::{
        error::{AppError, codes::device::DeviceAuthorizationErrorCode},
        openid_connect::device::{DeviceVerificationDecision, DeviceVerificationUser},
    },
    boot::AppState,
    domain::{
        auth::model::{ActiveSession, Login},
        openid_connect::ScopeSet,
    },
    web::{
        controllers::{
            response::json_response,
            shared::{csrf_token, load_active_session_entries},
        },
        views::oauth2::{
            ConsentApiResponse, ConsentDecision, DeviceConsentAccount, DeviceConsentPageData,
            build_scope_display,
        },
    },
};

pub(super) async fn device_consent_api(
    ctx: &AppState,
    _headers: &HeaderMap,
    depot: &Depot,
    user_code: &str,
) -> Result<salvo::Response, AppError> {
    let description = ctx
        .services()
        .oidc_device_authorization()
        .describe_verification(user_code)
        .await?;
    Ok(json_response(
        StatusCode::OK,
        serde_json::json!({
            "user_code": description.user_code,
            "status": description.status,
            "csrf_token": csrf_token(depot),
        }),
    ))
}

pub(super) async fn device_login_consent_api(
    ctx: &AppState,
    headers: &HeaderMap,
    depot: &Depot,
    login_id: &str,
    login: &Login,
) -> Result<salvo::Response, AppError> {
    let description = ctx
        .services()
        .oidc_device_authorization()
        .describe_login(login)
        .await?;
    let actor = verification_actor(ctx, headers, login).await?;
    let scope = ScopeSet::parse(&description.scopes.join(" ")).unwrap_or_default();
    Ok(json_response(
        StatusCode::OK,
        DeviceConsentPageData {
            login_id: login_id.to_owned(),
            user_code: description.user_code,
            status: description.status,
            consent_required: description.consent_required,
            client_name: description.client_name,
            logo_uri: description.logo_uri,
            client_uri: description.client_uri,
            scopes: build_scope_display(&scope),
            csrf_token: csrf_token(depot),
            account: DeviceConsentAccount {
                name: actor.user_name,
                email: actor.user_email,
                picture: actor.user_picture,
            },
        },
    ))
}

pub(super) async fn device_consent_submit(
    ctx: &AppState,
    headers: &HeaderMap,
    login: &Login,
    decision: ConsentDecision,
) -> Result<salvo::Response, AppError> {
    let actor = verification_actor(ctx, headers, login).await?;
    let decision = match decision {
        ConsentDecision::Approve => DeviceVerificationDecision::Approve,
        ConsentDecision::Deny => DeviceVerificationDecision::Deny,
    };
    ctx.services()
        .oidc_device_authorization()
        .decide_login(
            login,
            &DeviceVerificationUser {
                user_oid: actor.user_oid,
                auth_time: Some(actor.authenticated_at.timestamp()),
                acr: actor.acr,
                amr: actor.amr,
            },
            decision,
        )
        .await?;
    Ok(json_response(
        StatusCode::OK,
        ConsentApiResponse {
            status: match decision {
                DeviceVerificationDecision::Approve => "approved",
                DeviceVerificationDecision::Deny => "denied",
            },
            continue_uri: None,
            error: None,
        },
    ))
}

async fn verification_actor(
    ctx: &AppState,
    headers: &HeaderMap,
    login: &Login,
) -> Result<ActiveSession, AppError> {
    let entries = load_active_session_entries(ctx, headers).await?;
    entries
        .into_iter()
        .find(|entry| {
            Some(entry.session.session_oid) == login.session_oid
                && Some(entry.session.user_oid) == login.user_oid
        })
        .map(|entry| entry.session)
        .ok_or_else(|| AppError::from_code(DeviceAuthorizationErrorCode::VerificationLoginRequired))
}
