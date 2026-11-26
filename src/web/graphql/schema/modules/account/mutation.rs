use crate::graphql::schema::access::access;
use async_graphql::{Context, Object, Result};
use identity_application::error::codes::graphql;
use identity_domain::openid_connect::ApiScope;

use identity_application::authentication::email_verification::EmailChange;

use super::email_verification::{
    CancelEmailVerificationInput, CancelEmailVerificationPayload, EmailVerificationRequest,
    SendEmailVerificationInput, SendEmailVerificationPayload, UpdateEmailPayload,
};
use super::types::{
    UpdateEmailInput, UpdateProfileInput, UpdateProfilePayload, UpdateUsernameInput, UserNode,
};
use crate::graphql::schema::{
    authorization::{RecentAuthenticationGuard, ScopeGuard, UserPrincipalGuard, request_context},
    error::{app_error, coded_error},
};

#[derive(Default)]
pub(crate) struct AccountMutation;

#[Object]
impl AccountMutation {
    #[graphql(
        guard = "UserPrincipalGuard.and(ScopeGuard::new(ApiScope::UserWrite)).and(RecentAuthenticationGuard::new())",
        directive = access::apply(ScopeGuard::policy(ApiScope::UserWrite)),
        directive = access::apply(RecentAuthenticationGuard::new().policy())
    )]
    async fn update_username(
        &self,
        ctx: &Context<'_>,
        input: UpdateUsernameInput,
    ) -> Result<UpdateProfilePayload> {
        let request = request_context(ctx)?;
        let user = request
            .state
            .services()
            .account()
            .update_username(request.user_oid()?, &input.username)
            .await
            .map_err(|error| app_error(ctx, error))?;
        Ok(UpdateProfilePayload::new(
            UserNode::from(user),
            input.client_mutation_id,
        ))
    }

    #[graphql(
        guard = "UserPrincipalGuard.and(ScopeGuard::new(ApiScope::UserWrite)).and(RecentAuthenticationGuard::new())",
        directive = access::apply(ScopeGuard::policy(ApiScope::UserWrite)),
        directive = access::apply(RecentAuthenticationGuard::new().policy())
    )]
    /// Change the account's email address. While this instance can send
    /// email, a verification link goes to the new address and the current
    /// address stays until it is followed; otherwise the address is replaced
    /// at once and is unverified.
    async fn update_email(
        &self,
        ctx: &Context<'_>,
        input: UpdateEmailInput,
    ) -> Result<UpdateEmailPayload> {
        let request = request_context(ctx)?;
        let change = request
            .state
            .services()
            .account()
            .update_email(
                request.user_oid()?,
                &input.email,
                vec![request.locale.to_string()],
            )
            .await
            .map_err(|error| app_error(ctx, error))?;
        let (user, verification) = match change {
            EmailChange::Changed(user) => (*user, None),
            EmailChange::VerificationSent(sent) => (
                request.user()?.clone(),
                Some(EmailVerificationRequest::from(sent)),
            ),
        };
        Ok(UpdateEmailPayload {
            user: UserNode::from(user),
            verification,
            client_mutation_id: input.client_mutation_id,
        })
    }

    /// Email a new verification link: to the address of a pending change, or
    /// else to the account's current address.
    #[graphql(
        guard = "UserPrincipalGuard.and(ScopeGuard::new(ApiScope::UserWrite))",
        directive = access::apply(ScopeGuard::policy(ApiScope::UserWrite))
    )]
    async fn send_email_verification(
        &self,
        ctx: &Context<'_>,
        input: SendEmailVerificationInput,
    ) -> Result<SendEmailVerificationPayload> {
        let request = request_context(ctx)?;
        let sent = request
            .state
            .services()
            .account()
            .send_email_verification(request.user_oid()?, vec![request.locale.to_string()])
            .await
            .map_err(|error| app_error(ctx, error))?;
        Ok(SendEmailVerificationPayload {
            verification: EmailVerificationRequest::from(sent),
            client_mutation_id: input.client_mutation_id,
        })
    }

    /// Withdraw the verification in progress; its link stops working and a
    /// pending address change is discarded.
    #[graphql(
        guard = "UserPrincipalGuard.and(ScopeGuard::new(ApiScope::UserWrite))",
        directive = access::apply(ScopeGuard::policy(ApiScope::UserWrite))
    )]
    async fn cancel_email_verification(
        &self,
        ctx: &Context<'_>,
        input: CancelEmailVerificationInput,
    ) -> Result<CancelEmailVerificationPayload> {
        let request = request_context(ctx)?;
        let cancelled = request
            .state
            .services()
            .account()
            .cancel_email_verification(request.user_oid()?)
            .await
            .map_err(|error| app_error(ctx, error))?;
        Ok(CancelEmailVerificationPayload {
            cancelled,
            client_mutation_id: input.client_mutation_id,
        })
    }

    #[graphql(guard = "UserPrincipalGuard.and(ScopeGuard::new(ApiScope::UserWrite))",
        directive = access::apply(ScopeGuard::policy(ApiScope::UserWrite)))]
    async fn update_profile(
        &self,
        ctx: &Context<'_>,
        input: UpdateProfileInput,
    ) -> Result<UpdateProfilePayload> {
        let patch = input
            .clone()
            .into_patch()
            .map_err(|()| coded_error(ctx, graphql::error::InvalidTheme))?;
        let request = request_context(ctx)?;
        let user = request
            .state
            .services()
            .account()
            .update_profile(request.user_oid()?, patch)
            .await
            .map_err(|error| app_error(ctx, error))?;
        Ok(UpdateProfilePayload::new(
            UserNode::from(user),
            input.client_mutation_id,
        ))
    }
}
