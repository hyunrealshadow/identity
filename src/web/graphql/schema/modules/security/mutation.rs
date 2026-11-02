use crate::graphql::schema::access::{AccessPolicy, access};
use async_graphql::{Context, Object, Result};
use identity_application::error::{codes::graphql::GraphqlErrorCode, params::ErrorParams};
use identity_domain::openid_connect::ApiScope;

use super::types::{
    BeginTotpEnrollmentPayload, ChangePasswordInput, ChangePasswordPayload,
    ChangeTotpEnrollmentAlgorithmInput, ConfirmTotpEnrollmentInput, RecoveryCodeEnrollmentPayload,
    RecoveryCodesPayload, TotpChangedPayload,
};
use crate::graphql::schema::{
    authorization::{
        MfaRecentAuthenticationGuard, RecentAuthenticationGuard, ScopeGuard, UserPrincipalGuard,
        request_context,
    },
    error::{app_error, coded_error},
};

#[derive(Default)]
pub(crate) struct SecurityMutation;

#[Object]
impl SecurityMutation {
    #[graphql(
        guard = "UserPrincipalGuard.and(ScopeGuard::new(ApiScope::AccountUpdate)).and(MfaRecentAuthenticationGuard)",
        directive = access::apply(ScopeGuard::policy(ApiScope::AccountUpdate)),
        directive = access::apply(AccessPolicy::account_security())
    )]
    async fn prepare_mfa_management(&self, ctx: &Context<'_>) -> Result<bool> {
        let _ = request_context(ctx)?;
        Ok(true)
    }

    #[graphql(
        guard = "UserPrincipalGuard.and(ScopeGuard::new(ApiScope::AccountUpdate)).and(MfaRecentAuthenticationGuard)",
        directive = access::apply(ScopeGuard::policy(ApiScope::AccountUpdate)),
        directive = access::apply(AccessPolicy::account_security())
    )]
    async fn prepare_mfa_recovery_codes(
        &self,
        ctx: &Context<'_>,
    ) -> Result<RecoveryCodeEnrollmentPayload> {
        let request = request_context(ctx)?;
        let enrollment = request
            .state
            .services()
            .mfa()
            .prepare_recovery_code_enrollment(request.user_oid()?)
            .await
            .map_err(|error| app_error(ctx, error))?;
        Ok(RecoveryCodeEnrollmentPayload {
            recovery_codes: enrollment.recovery_codes,
            enrollment_token: enrollment.enrollment_token,
        })
    }

    #[graphql(guard = "UserPrincipalGuard.and(ScopeGuard::new(ApiScope::AccountUpdate))",
        directive = access::apply(ScopeGuard::policy(ApiScope::AccountUpdate)))]
    async fn update_preferred_mfa_method(
        &self,
        ctx: &Context<'_>,
        method: PreferredMfaMethod,
    ) -> Result<bool> {
        let request = request_context(ctx)?;
        request
            .state
            .services()
            .account()
            .update_profile(
                request.user_oid()?,
                identity_domain::user::repository::UserProfilePatch {
                    preferred_mfa_method: Some(match method {
                        PreferredMfaMethod::Passkey => identity_domain::user::MfaMethod::Passkey,
                        PreferredMfaMethod::Otp => identity_domain::user::MfaMethod::Otp,
                    }),
                    ..Default::default()
                },
            )
            .await
            .map_err(|error| app_error(ctx, error))?;
        Ok(true)
    }

    #[graphql(
        guard = "UserPrincipalGuard.and(ScopeGuard::new(ApiScope::AccountUpdate)).and(MfaRecentAuthenticationGuard)",
        directive = access::apply(ScopeGuard::policy(ApiScope::AccountUpdate)),
        directive = access::apply(AccessPolicy::account_security())
    )]
    async fn begin_passkey_registration(
        &self,
        ctx: &Context<'_>,
        #[graphql(validator(chars_max_length = 4096))] recovery_enrollment_token: Option<String>,
    ) -> Result<async_graphql::Json<serde_json::Value>> {
        let request = request_context(ctx)?;
        let session = request.claims.session_oid.ok_or_else(|| {
            coded_error(
                ctx,
                GraphqlErrorCode::BrowserSessionRequired,
                ErrorParams::new(),
            )
        })?;
        let recovery_codes = request
            .state
            .services()
            .mfa()
            .registration_recovery_codes(request.user_oid()?, recovery_enrollment_token.as_deref())
            .await
            .map_err(|error| app_error(ctx, error))?;
        let options = request
            .state
            .services()
            .passkey()
            .begin_registration(
                request.user_oid()?,
                session.0,
                &request.user()?.email,
                recovery_codes,
            )
            .await
            .map_err(|error| app_error(ctx, error))?;
        Ok(async_graphql::Json(serde_json::to_value(options).map_err(
            |_| {
                coded_error(
                    ctx,
                    GraphqlErrorCode::SerializationFailed,
                    ErrorParams::new(),
                )
            },
        )?))
    }

    #[graphql(
        guard = "UserPrincipalGuard.and(ScopeGuard::new(ApiScope::AccountUpdate)).and(MfaRecentAuthenticationGuard)",
        directive = access::apply(ScopeGuard::policy(ApiScope::AccountUpdate)),
        directive = access::apply(AccessPolicy::account_security())
    )]
    async fn finish_passkey_registration(
        &self,
        ctx: &Context<'_>,
        #[graphql(validator(chars_max_length = 128))] challenge_id: String,
        #[graphql(validator(chars_max_length = 255))] name: String,
        credential: async_graphql::Json<serde_json::Value>,
    ) -> Result<bool> {
        let request = request_context(ctx)?;
        let session = request.claims.session_oid.ok_or_else(|| {
            coded_error(
                ctx,
                GraphqlErrorCode::BrowserSessionRequired,
                ErrorParams::new(),
            )
        })?;
        let challenge = uuid::Uuid::parse_str(&challenge_id).map_err(|_| {
            coded_error(
                ctx,
                GraphqlErrorCode::InvalidPasskeyChallenge,
                ErrorParams::new(),
            )
        })?;
        request
            .state
            .services()
            .passkey()
            .finish_registration(
                request.user_oid()?,
                session.0,
                challenge,
                &name,
                credential.0,
            )
            .await
            .map_err(|error| app_error(ctx, error))?;
        Ok(true)
    }

    #[graphql(
        guard = "UserPrincipalGuard.and(ScopeGuard::new(ApiScope::AccountUpdate)).and(MfaRecentAuthenticationGuard)",
        directive = access::apply(ScopeGuard::policy(ApiScope::AccountUpdate)),
        directive = access::apply(AccessPolicy::account_security())
    )]
    async fn delete_passkey(
        &self,
        ctx: &Context<'_>,
        #[graphql(validator(chars_max_length = 128))] id: String,
    ) -> Result<bool> {
        let request = request_context(ctx)?;
        let id = uuid::Uuid::parse_str(&id).map_err(|_| {
            coded_error(ctx, GraphqlErrorCode::InvalidPasskeyId, ErrorParams::new())
        })?;
        request
            .state
            .services()
            .passkey()
            .delete(request.user_oid()?, id)
            .await
            .map_err(|error| app_error(ctx, error))
    }

    #[graphql(
        guard = "UserPrincipalGuard.and(ScopeGuard::new(ApiScope::PasswordChange)).and(MfaRecentAuthenticationGuard)",
        directive = access::apply(ScopeGuard::policy(ApiScope::PasswordChange)),
        directive = access::apply(AccessPolicy::account_security())
    )]
    async fn change_password(
        &self,
        ctx: &Context<'_>,
        input: ChangePasswordInput,
    ) -> Result<ChangePasswordPayload> {
        let request = request_context(ctx)?;
        let session_oid = request.claims.session_oid.ok_or_else(|| {
            coded_error(
                ctx,
                GraphqlErrorCode::BrowserSessionRequired,
                ErrorParams::new(),
            )
        })?;
        let outcome = request
            .state
            .services()
            .login()
            .change_password_with_session_revocation(
                request.user_oid()?,
                &input.new_password,
                session_oid,
            )
            .await
            .map_err(|error| app_error(ctx, error))?;
        Ok(ChangePasswordPayload::new(
            outcome.revoked_other_sessions,
            outcome.session_revocation_failures,
            input.client_mutation_id,
        ))
    }

    #[graphql(
        guard = "UserPrincipalGuard.and(ScopeGuard::new(ApiScope::AccountUpdate)).and(MfaRecentAuthenticationGuard)",
        directive = access::apply(ScopeGuard::policy(ApiScope::AccountUpdate)),
        directive = access::apply(AccessPolicy::account_security())
    )]
    async fn begin_totp_enrollment(
        &self,
        ctx: &Context<'_>,
        #[graphql(validator(chars_max_length = 255))] client_mutation_id: Option<String>,
    ) -> Result<BeginTotpEnrollmentPayload> {
        let request = request_context(ctx)?;
        let issuer = request
            .state
            .services()
            .oidc()
            .issuer()
            .map_err(|error| app_error(ctx, error))?;
        let enrollment = request
            .state
            .services()
            .mfa()
            .begin_totp_enrollment(
                request.user_oid()?,
                issuer.host_str().unwrap_or("Identity"),
                &request.user()?.email,
            )
            .await
            .map_err(|error| app_error(ctx, error))?;
        Ok(BeginTotpEnrollmentPayload::new(
            enrollment.secret,
            enrollment.otp_auth_uri,
            enrollment.enrollment_token,
            enrollment.recovery_codes,
            client_mutation_id,
        ))
    }

    #[graphql(
        guard = "UserPrincipalGuard.and(ScopeGuard::new(ApiScope::AccountUpdate)).and(MfaRecentAuthenticationGuard)",
        directive = access::apply(ScopeGuard::policy(ApiScope::AccountUpdate)),
        directive = access::apply(AccessPolicy::account_security())
    )]
    async fn confirm_totp_enrollment(
        &self,
        ctx: &Context<'_>,
        input: ConfirmTotpEnrollmentInput,
    ) -> Result<RecoveryCodesPayload> {
        let request = request_context(ctx)?;
        let confirmed = request
            .state
            .services()
            .mfa()
            .confirm_totp_enrollment(request.user_oid()?, &input.enrollment_token, &input.code)
            .await
            .map_err(|error| app_error(ctx, error))?;
        Ok(RecoveryCodesPayload::new(
            confirmed.recovery_codes,
            input.client_mutation_id,
        ))
    }

    #[graphql(
        guard = "UserPrincipalGuard.and(ScopeGuard::new(ApiScope::AccountUpdate)).and(MfaRecentAuthenticationGuard)",
        directive = access::apply(ScopeGuard::policy(ApiScope::AccountUpdate)),
        directive = access::apply(AccessPolicy::account_security())
    )]
    async fn change_totp_enrollment_algorithm(
        &self,
        ctx: &Context<'_>,
        input: ChangeTotpEnrollmentAlgorithmInput,
    ) -> Result<BeginTotpEnrollmentPayload> {
        let request = request_context(ctx)?;
        let issuer = request
            .state
            .services()
            .oidc()
            .issuer()
            .map_err(|error| app_error(ctx, error))?;
        let enrollment = request
            .state
            .services()
            .mfa()
            .change_totp_enrollment_algorithm(
                request.user_oid()?,
                &input.enrollment_token,
                issuer.host_str().unwrap_or("Identity"),
                &request.user()?.email,
                input.algorithm.into(),
            )
            .await
            .map_err(|error| app_error(ctx, error))?;
        Ok(BeginTotpEnrollmentPayload::new(
            enrollment.secret,
            enrollment.otp_auth_uri,
            enrollment.enrollment_token,
            enrollment.recovery_codes,
            input.client_mutation_id,
        ))
    }

    #[graphql(
        guard = "UserPrincipalGuard.and(ScopeGuard::new(ApiScope::AccountUpdate)).and(RecentAuthenticationGuard::aal2())",
        directive = access::apply(ScopeGuard::policy(ApiScope::AccountUpdate)),
        directive = access::apply(RecentAuthenticationGuard::aal2().policy())
    )]
    async fn disable_totp(
        &self,
        ctx: &Context<'_>,
        #[graphql(validator(chars_max_length = 255))] client_mutation_id: Option<String>,
    ) -> Result<TotpChangedPayload> {
        let request = request_context(ctx)?;
        request
            .state
            .services()
            .mfa()
            .disable_totp(request.user_oid()?)
            .await
            .map_err(|error| app_error(ctx, error))?;
        Ok(TotpChangedPayload::new(client_mutation_id))
    }

    #[graphql(
        guard = "UserPrincipalGuard.and(ScopeGuard::new(ApiScope::AccountUpdate)).and(RecentAuthenticationGuard::aal2())",
        directive = access::apply(ScopeGuard::policy(ApiScope::AccountUpdate)),
        directive = access::apply(RecentAuthenticationGuard::aal2().policy())
    )]
    async fn regenerate_recovery_codes(
        &self,
        ctx: &Context<'_>,
        #[graphql(validator(chars_max_length = 255))] client_mutation_id: Option<String>,
    ) -> Result<RecoveryCodesPayload> {
        let request = request_context(ctx)?;
        let regenerated = request
            .state
            .services()
            .mfa()
            .regenerate_recovery_codes(request.user_oid()?)
            .await
            .map_err(|error| app_error(ctx, error))?;
        Ok(RecoveryCodesPayload::new(
            regenerated.recovery_codes,
            client_mutation_id,
        ))
    }
}

#[derive(Clone, Copy, PartialEq, Eq, async_graphql::Enum)]
pub(crate) enum PreferredMfaMethod {
    Passkey,
    Otp,
}
