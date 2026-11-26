//! Authentication controller handlers.
//!
//! All handlers follow the progressive login flow:
//! 1. `GET  /api/auth/sessions/active`  – list active accounts from `X-Sessions`
//! 2. `POST /api/auth/login/select`     – select an existing session
//! 3. `POST /api/auth/login/identifier` – validate identifier, create login
//! 4. `POST /api/auth/login/email-code` – email a sign-in code and link
//!    (optional first factor)
//!    `POST /api/auth/login/password-reset[/check|/confirm]` – email a link
//!    that replaces a forgotten password, then set the new one
//!    `POST /api/auth/login/registration[/check|/confirm]` – email a link
//!    that verifies the address of a new account, then create it
//! 5. `POST /api/auth/login/challenge`  – verify credential, create session
//! 6. `POST /api/auth/login/mfa-enrollment[/confirm]` – enroll a missing
//!    second factor when the request requires `aal2`
//! 7. `POST /api/auth/login/passkey-enrollment[/confirm]` – register a passkey
//!    when the request requires `phr`

use http::{HeaderMap, StatusCode};
use identity_domain::auth::LoginStatus;
use salvo::{Depot, Request, Response, Router, handler};
use url::form_urlencoded::Serializer;
use urlencoding::encode;

use super::{
    response::{JsonWebResult, app_state, parse_json, parse_param, render_json},
    shared::{
        api_csrf_middleware, build_selected_session_state, build_session_context, csrf_token,
        load_active_session_entries, parse_session_header, protocol_continue_uri,
        unprotect_session_id,
    },
};
use crate::{
    application::{
        authentication::{login, login::ChallengeOutcome},
        error::{
            AppError,
            codes::{auth, authorize_http},
        },
        openid_connect::authorize::stored_request_has_prompt,
        user::CredentialType,
    },
    domain::{
        client_authorization::SelectionSource, openid_connect::PromptValue, user::model::UserOid,
    },
    middleware::resolved_client_ip,
    views::auth::{
        AccountItem, ActiveAccountsResponse, ChallengeRequest, ChallengeResponse,
        EmailCodeRequest as EmailCodeRequestBody, EmailCodeResponse, IdentifierRequest,
        IdentifierResponse, LoginClientDisplay, LoginStatusResponse, MfaEnrollmentAlgorithmRequest,
        MfaEnrollmentConfirmRequest, MfaEnrollmentRequest, MfaEnrollmentResponse,
        PasskeyEnrollmentConfirmRequest, PasskeyEnrollmentResponse, PasswordResetCheckRequest,
        PasswordResetConfirmRequest, PasswordResetStatusResponse, RegistrationCheckRequest,
        RegistrationCheckResponse, RegistrationConfirmRequest,
        RegistrationRequest as RegistrationRequestBody, RequiredPasswordChangeRequest,
        RestartLoginRequest, RestartLoginResponse, SelectAccountRequest, SelectAccountResponse,
        SessionInfo, SwitchLoginRequest, SwitchLoginResponse, UserDisplayInfo,
    },
};

// ─── Routes ──────────────────────────────────────────────────────────────────

pub fn routes() -> Router {
    Router::new()
        .hoop(api_csrf_middleware())
        .push(Router::with_path("api/auth/sessions/active").get(active_sessions))
        .push(Router::with_path("api/auth/login/{id}").get(login_status))
        .push(Router::with_path("api/auth/login/select").post(select_account))
        .push(Router::with_path("api/auth/login/identifier").post(identifier))
        .push(Router::with_path("api/auth/login/challenge").post(challenge))
        .push(Router::with_path("api/auth/login/email-code").post(email_code))
        .push(Router::with_path("api/auth/login/password-reset").post(password_reset))
        .push(Router::with_path("api/auth/login/password-change").post(required_password_change))
        .push(Router::with_path("api/auth/login/password-reset/check").post(check_password_reset))
        .push(
            Router::with_path("api/auth/login/password-reset/confirm").post(confirm_password_reset),
        )
        .push(Router::with_path("api/auth/login/registration").post(registration))
        .push(Router::with_path("api/auth/login/registration/check").post(check_registration))
        .push(Router::with_path("api/auth/login/registration/confirm").post(confirm_registration))
        .push(Router::with_path("api/auth/login/passkey/options").post(passkey_options))
        .push(Router::with_path("api/auth/login/restart").post(restart_login))
        .push(Router::with_path("api/auth/login/switch").post(switch_login))
        .push(Router::with_path("api/auth/login/mfa-enrollment").post(mfa_enrollment))
        .push(
            Router::with_path("api/auth/login/mfa-enrollment/algorithm")
                .post(change_mfa_enrollment_algorithm),
        )
        .push(
            Router::with_path("api/auth/login/mfa-enrollment/confirm").post(confirm_mfa_enrollment),
        )
        .push(Router::with_path("api/auth/login/passkey-enrollment").post(passkey_enrollment))
        .push(
            Router::with_path("api/auth/login/passkey-enrollment/confirm")
                .post(confirm_passkey_enrollment),
        )
}

mod sign_in;
use sign_in::*;
mod recovery;
use recovery::*;
mod challenge;
use challenge::*;
mod enrollment;
use enrollment::*;
#[cfg(test)]
mod tests;
