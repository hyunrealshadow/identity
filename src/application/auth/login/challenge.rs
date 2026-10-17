use super::{ChallengeOutcome, LoginService, SessionContext};
use crate::setting::PasswordHashSetting;
use crate::{
    error::{AppError, code::AppErrorCode as _, codes::auth::AuthErrorCode},
    observability::{BusinessEvent, EventValue, error_outcome},
    user::model::CredentialType,
};
use chrono::Utc;
use identity_domain::auth::LoginStatus;
use tracing::error;
use uuid::Uuid;

impl LoginService {
    /// Step 2: Verify a credential and either create a session or signal that
    /// MFA is required.
    ///
    /// The user is resolved from the login record itself (via `login.user_oid`)
    /// so no identifier string needs to be re-submitted by the client.
    ///
    /// # Password flow
    /// - If the user has an OTP credential: returns [`ChallengeOutcome::MfaRequired`].
    /// - Otherwise: renews a matching browser session or creates a new session,
    ///   with `acr = ACR_AAL1` and returns
    ///   [`ChallengeOutcome::Authenticated`].
    ///
    /// # OTP flow
    /// The login status MUST already be `mfa_required` (set by a prior
    /// password challenge). Up to [`identity_domain::auth::MAX_OTP_ATTEMPTS`] invalid codes are allowed
    /// per login flow; further attempts return [`AuthErrorCode::TooManyAttempts`]
    /// and invalidate the login. Creates or refreshes the bound session with
    /// `acr = ACR_AAL2` and an internal expiry on success.
    #[tracing::instrument(skip_all, name = "authentication.challenge")]
    pub async fn challenge(
        &self,
        login_oid: Uuid,
        credential_type: CredentialType,
        credential: &str,
        ctx: SessionContext,
    ) -> Result<ChallengeOutcome, AppError> {
        let result = self
            .challenge_inner(login_oid, credential_type, credential, ctx)
            .await;
        self.record_authentication_result(login_oid, credential_type, &result);
        result
    }

    /// Emit the authentication result and session establishment events. The
    /// events never carry credentials, OTP codes or recovery codes.
    fn record_authentication_result(
        &self,
        login_oid: Uuid,
        credential_type: CredentialType,
        result: &Result<ChallengeOutcome, AppError>,
    ) {
        let factor = match credential_type {
            CredentialType::Password => "password",
            CredentialType::Otp => "otp",
            CredentialType::RecoveryCode => "recovery_code",
            CredentialType::Passkey => "passkey",
        };
        match result {
            Ok(ChallengeOutcome::Authenticated { login, session }) => {
                let user_oid = login
                    .user_oid
                    .map(|oid| oid.to_string())
                    .unwrap_or_default();
                self.events.emit(
                    BusinessEvent::audit("authentication.result")
                        .attribute("login_oid", EventValue::Text(login_oid.to_string()))
                        .outcome("success")
                        .reason("authenticated")
                        .attribute("factor", EventValue::Text(factor.to_owned()))
                        .attribute(
                            "user_oid",
                            EventValue::Pseudonymized {
                                purpose: "user_oid",
                                value: user_oid.clone(),
                            },
                        )
                        .attribute(
                            "session_oid",
                            EventValue::Pseudonymized {
                                purpose: "session_oid",
                                value: session.oid.0.to_string(),
                            },
                        )
                        .attribute(
                            "acr",
                            EventValue::Text(session.acr.clone().unwrap_or_default()),
                        ),
                );
                self.events.emit(
                    BusinessEvent::business("session.established")
                        .attribute("login_oid", EventValue::Text(login_oid.to_string()))
                        .outcome("success")
                        .attribute(
                            "user_oid",
                            EventValue::Pseudonymized {
                                purpose: "user_oid",
                                value: user_oid,
                            },
                        )
                        .attribute(
                            "session_oid",
                            EventValue::Pseudonymized {
                                purpose: "session_oid",
                                value: session.oid.0.to_string(),
                            },
                        ),
                );
            }
            Ok(ChallengeOutcome::MfaRequired { login }) => {
                self.events.emit(
                    BusinessEvent::audit("authentication.result")
                        .attribute("login_oid", EventValue::Text(login_oid.to_string()))
                        .outcome("success")
                        .reason("mfa_required")
                        .attribute("factor", EventValue::Text(factor.to_owned()))
                        .attribute(
                            "user_oid",
                            EventValue::Pseudonymized {
                                purpose: "user_oid",
                                value: login
                                    .user_oid
                                    .map(|oid| oid.to_string())
                                    .unwrap_or_default(),
                            },
                        ),
                );
            }
            Err(error) => {
                let (outcome, reason) = authentication_outcome(error);
                self.events.emit(
                    BusinessEvent::audit("authentication.result")
                        .attribute("login_oid", EventValue::Text(login_oid.to_string()))
                        .outcome(outcome)
                        .reason(reason)
                        .attribute("factor", EventValue::Text(factor.to_owned()))
                        .attribute("error_code", EventValue::Integer(i64::from(error.code()))),
                );
            }
        }
    }

    async fn challenge_inner(
        &self,
        login_oid: Uuid,
        credential_type: CredentialType,
        credential: &str,
        ctx: SessionContext,
    ) -> Result<ChallengeOutcome, AppError> {
        // Look up the login record (carries user_oid — no extra identifier needed).
        let login = self
            .login_repo
            .find_by_oid(login_oid)
            .await?
            .ok_or_else(|| AppError::from_code(AuthErrorCode::InvalidLoginState))?;

        if login.user_oid.is_none() {
            return Err(AppError::from_code(AuthErrorCode::InvalidLoginState));
        }

        // Check login expiry for all credential types.
        if login.expires_at <= Utc::now() {
            if let Err(e) = self
                .login_repo
                .update_status(login.oid, LoginStatus::EXPIRED, None, None)
                .await
            {
                error!(error = %e, "failed to update login status on expiry");
            }
            return Err(AppError::from_code(AuthErrorCode::LoginExpired));
        }

        let hash_options = self.settings.snapshot().get::<PasswordHashSetting>();

        match credential_type {
            CredentialType::Passkey => self.challenge_passkey(login, credential, ctx).await,
            CredentialType::Password => {
                self.challenge_password(login, credential, &hash_options, ctx)
                    .await
            }
            CredentialType::Otp => self.challenge_otp(login, credential, ctx).await,
            CredentialType::RecoveryCode => {
                self.challenge_recovery_code(login, credential, ctx).await
            }
        }
    }
}

/// Bounded reason categories for authentication failures. Expected credential
/// rejections stay `rejected`; only unexpected internal failures are
/// `failure`.
fn authentication_outcome(error: &AppError) -> (&'static str, &'static str) {
    match error.code() {
        code if code == AuthErrorCode::InvalidCredential.code() => {
            ("rejected", "invalid_credential")
        }
        code if code == AuthErrorCode::InvalidOtp.code() => ("rejected", "invalid_credential"),
        code if code == AuthErrorCode::TooManyAttempts.code() => ("rejected", "too_many_attempts"),
        code if code == AuthErrorCode::UserLocked.code() => ("rejected", "account_locked"),
        code if code == AuthErrorCode::UserDisabled.code() => ("rejected", "account_disabled"),
        code if code == AuthErrorCode::LoginExpired.code() => ("rejected", "login_expired"),
        code if code == AuthErrorCode::InvalidLoginState.code() => ("rejected", "invalid_state"),
        code if code == AuthErrorCode::UserNotFound.code() => ("rejected", "not_found"),
        _ => error_outcome(error),
    }
}
