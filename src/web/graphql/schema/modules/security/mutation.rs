use async_graphql::{Context, Object, Result};
use identity_domain::openid_connect::ApiScope;
use identity_infrastructure::database::repository::session::SessionRepositoryImpl;
use uuid::Uuid;

use super::types::{
    BeginTotpEnrollmentPayload, ChangePasswordInput, ChangePasswordPayload,
    ChangeTotpEnrollmentAlgorithmInput, ConfirmTotpEnrollmentInput, RecoveryCodesPayload,
    TotpChangedPayload,
};
use crate::graphql::schema::{
    authorization::{request_context, require_recent_authentication, require_scope},
    error::{app_error, internal_error},
};

#[derive(Default)]
pub(crate) struct SecurityMutation;

#[Object]
impl SecurityMutation {
    async fn change_password(
        &self,
        ctx: &Context<'_>,
        input: ChangePasswordInput,
    ) -> Result<ChangePasswordPayload> {
        require_scope(ctx, ApiScope::PasswordChange)?;
        let request = request_context(ctx)?;
        require_recent_authentication(ctx, None)?;
        request
            .state
            .services()
            .login()
            .change_password(
                request.claims.user_oid,
                &input.current_password,
                &input.new_password,
            )
            .await
            .map_err(|error| app_error(ctx, error))?;

        let repo = SessionRepositoryImpl::new(request.state.resources().db().clone());
        let sessions = repo
            .list_by_user_oid(Uuid::from(request.claims.user_oid))
            .await
            .map_err(internal_error)?;
        for session in sessions
            .into_iter()
            .filter(|session| session.oid != request.claims.session_oid)
            .filter(|session| session.revoked_at.is_none())
        {
            request
                .state
                .services()
                .session()
                .revoke(session.oid)
                .await
                .map_err(internal_error)?;
        }
        Ok(ChangePasswordPayload::new(input.client_mutation_id))
    }

    async fn begin_totp_enrollment(
        &self,
        ctx: &Context<'_>,
        client_mutation_id: Option<String>,
    ) -> Result<BeginTotpEnrollmentPayload> {
        require_scope(ctx, ApiScope::AccountUpdate)?;
        require_recent_authentication(ctx, None)?;
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
        require_scope(ctx, ApiScope::AccountUpdate)?;
        require_recent_authentication(ctx, None)?;
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
        require_scope(ctx, ApiScope::AccountUpdate)?;
        require_recent_authentication(ctx, None)?;
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
        require_recent_authentication(ctx, Some(identity_domain::auth::ACR_AAL2))?;
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
}
