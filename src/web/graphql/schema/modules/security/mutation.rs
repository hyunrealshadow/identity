use async_graphql::{Context, Error, Object, Result};
use identity_domain::{auth::ACR_AAL2, openid_connect::ApiScope};

use super::types::{
    BeginTotpEnrollmentPayload, ChangePasswordInput, ChangePasswordPayload,
    ChangeTotpEnrollmentAlgorithmInput, ConfirmTotpEnrollmentInput, RecoveryCodesPayload,
    TotpChangedPayload,
};
use crate::graphql::schema::{
    authorization::{request_context, require_recent_authentication, require_scope},
    error::app_error,
};

#[derive(Default)]
pub(crate) struct SecurityMutation;

fn password_change_required_acr(mfa_enabled: bool) -> Option<&'static str> {
    mfa_enabled.then_some(ACR_AAL2)
}

#[Object]
impl SecurityMutation {
    async fn prepare_mfa_management(&self, ctx: &Context<'_>) -> Result<bool> {
        authorize_mfa_change(ctx).await?;
        Ok(true)
    }

    async fn update_preferred_mfa_method(
        &self,
        ctx: &Context<'_>,
        method: PreferredMfaMethod,
    ) -> Result<bool> {
        authorize_mfa_change(ctx).await?;
        let request = request_context(ctx)?;
        request
            .state
            .services()
            .account()
            .update_profile(
                request.claims.user_oid,
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

    async fn begin_passkey_registration(
        &self,
        ctx: &Context<'_>,
    ) -> Result<async_graphql::Json<serde_json::Value>> {
        authorize_mfa_change(ctx).await?;
        let request = request_context(ctx)?;
        let session = request
            .claims
            .session_oid
            .ok_or_else(|| Error::new("browser session required"))?;
        let options = request
            .state
            .services()
            .passkey()
            .begin_registration(request.claims.user_oid, session.0, &request.user.email)
            .await
            .map_err(|error| app_error(ctx, error))?;
        Ok(async_graphql::Json(
            serde_json::to_value(options).map_err(|_| Error::new("serialization failed"))?,
        ))
    }

    async fn finish_passkey_registration(
        &self,
        ctx: &Context<'_>,
        challenge_id: String,
        name: String,
        credential: async_graphql::Json<serde_json::Value>,
    ) -> Result<bool> {
        authorize_mfa_change(ctx).await?;
        let request = request_context(ctx)?;
        let session = request
            .claims
            .session_oid
            .ok_or_else(|| Error::new("browser session required"))?;
        let challenge =
            uuid::Uuid::parse_str(&challenge_id).map_err(|_| Error::new("invalid challenge"))?;
        request
            .state
            .services()
            .passkey()
            .finish_registration(
                request.claims.user_oid,
                session.0,
                challenge,
                &name,
                credential.0,
            )
            .await
            .map_err(|error| app_error(ctx, error))?;
        Ok(true)
    }

    async fn delete_passkey(&self, ctx: &Context<'_>, id: String) -> Result<bool> {
        authorize_mfa_change(ctx).await?;
        let request = request_context(ctx)?;
        let id = uuid::Uuid::parse_str(&id).map_err(|_| Error::new("invalid passkey"))?;
        request
            .state
            .services()
            .passkey()
            .delete(request.claims.user_oid, id)
            .await
            .map_err(|error| app_error(ctx, error))
    }

    async fn change_password(
        &self,
        ctx: &Context<'_>,
        input: ChangePasswordInput,
    ) -> Result<ChangePasswordPayload> {
        require_scope(ctx, ApiScope::PasswordChange)?;
        let request = request_context(ctx)?;
        let mfa_status = request
            .state
            .services()
            .mfa()
            .status(request.claims.user_oid)
            .await
            .map_err(|error| app_error(ctx, error))?;
        let has_passkeys = !request
            .state
            .services()
            .passkey()
            .list(request.claims.user_oid)
            .await
            .map_err(|error| app_error(ctx, error))?
            .is_empty();
        require_recent_authentication(
            ctx,
            password_change_required_acr(mfa_status.totp_enabled || has_passkeys),
        )?;
        let outcome = request
            .state
            .services()
            .login()
            .change_password_with_session_revocation(
                request.claims.user_oid,
                &input.new_password,
                request.claims.session_oid.ok_or_else(|| {
                    Error::new("this token was not issued from a browser session")
                })?,
            )
            .await
            .map_err(|error| app_error(ctx, error))?;
        Ok(ChangePasswordPayload::new(
            outcome.revoked_other_sessions,
            outcome.session_revocation_failures,
            input.client_mutation_id,
        ))
    }

    async fn begin_totp_enrollment(
        &self,
        ctx: &Context<'_>,
        client_mutation_id: Option<String>,
    ) -> Result<BeginTotpEnrollmentPayload> {
        authorize_mfa_change(ctx).await?;
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
                request.claims.user_oid,
                issuer.host_str().unwrap_or("Identity"),
                &request.user.email,
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

    async fn confirm_totp_enrollment(
        &self,
        ctx: &Context<'_>,
        input: ConfirmTotpEnrollmentInput,
    ) -> Result<RecoveryCodesPayload> {
        authorize_mfa_change(ctx).await?;
        let request = request_context(ctx)?;
        let confirmed = request
            .state
            .services()
            .mfa()
            .confirm_totp_enrollment(
                request.claims.user_oid,
                &input.enrollment_token,
                &input.code,
            )
            .await
            .map_err(|error| app_error(ctx, error))?;
        Ok(RecoveryCodesPayload::new(
            confirmed.recovery_codes,
            input.client_mutation_id,
        ))
    }

    async fn change_totp_enrollment_algorithm(
        &self,
        ctx: &Context<'_>,
        input: ChangeTotpEnrollmentAlgorithmInput,
    ) -> Result<BeginTotpEnrollmentPayload> {
        authorize_mfa_change(ctx).await?;
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
                request.claims.user_oid,
                &input.enrollment_token,
                issuer.host_str().unwrap_or("Identity"),
                &request.user.email,
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

    async fn disable_totp(
        &self,
        ctx: &Context<'_>,
        client_mutation_id: Option<String>,
    ) -> Result<TotpChangedPayload> {
        require_scope(ctx, ApiScope::AccountUpdate)?;
        require_recent_authentication(ctx, Some(ACR_AAL2))?;
        let request = request_context(ctx)?;
        request
            .state
            .services()
            .mfa()
            .disable_totp(request.claims.user_oid)
            .await
            .map_err(|error| app_error(ctx, error))?;
        Ok(TotpChangedPayload::new(client_mutation_id))
    }

    async fn regenerate_recovery_codes(
        &self,
        ctx: &Context<'_>,
        client_mutation_id: Option<String>,
    ) -> Result<RecoveryCodesPayload> {
        require_scope(ctx, ApiScope::AccountUpdate)?;
        require_recent_authentication(ctx, Some(ACR_AAL2))?;
        let request = request_context(ctx)?;
        let regenerated = request
            .state
            .services()
            .mfa()
            .regenerate_recovery_codes(request.claims.user_oid)
            .await
            .map_err(|error| app_error(ctx, error))?;
        Ok(RecoveryCodesPayload::new(
            regenerated.recovery_codes,
            client_mutation_id,
        ))
    }
}

#[cfg(test)]
mod tests {
    use identity_domain::auth::ACR_AAL2;

    use super::password_change_required_acr;

    #[test]
    fn password_change_requires_aal2_when_totp_is_enabled() {
        assert_eq!(password_change_required_acr(true), Some(ACR_AAL2));
        assert_eq!(password_change_required_acr(false), None);
    }
}

async fn authorize_mfa_change(ctx: &Context<'_>) -> Result<()> {
    require_scope(ctx, ApiScope::AccountUpdate)?;
    let request = request_context(ctx)?;
    let status = request
        .state
        .services()
        .mfa()
        .status(request.claims.user_oid)
        .await
        .map_err(|error| app_error(ctx, error))?;
    let has_passkeys = !request
        .state
        .services()
        .passkey()
        .list(request.claims.user_oid)
        .await
        .map_err(|error| app_error(ctx, error))?
        .is_empty();
    require_recent_authentication(
        ctx,
        (status.totp_enabled || has_passkeys).then_some(ACR_AAL2),
    )
}

#[derive(Clone, Copy, PartialEq, Eq, async_graphql::Enum)]
pub(crate) enum PreferredMfaMethod {
    Passkey,
    Otp,
}
