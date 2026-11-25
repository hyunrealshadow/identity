use async_graphql::{Context, Object, Result};
use identity_application::{
    authorization::ManagementTarget,
    setting::{
        email::{
            SendTestEmailCommand, SendTestEmailTemplate, UpdateEmailDeliveryCommand,
            UpdateEmailTemplateCommand,
        },
        management::{
            PasswordHashingView, UpdateAuthenticationSettingsCommand, UpdateProtocolSettingsCommand,
        },
    },
};
use identity_domain::authorization::ManagementScope;

use super::{
    email::{
        SendTestEmailInput, SendTestEmailPayload, UpdateEmailDeliverySettingsInput,
        UpdateEmailTemplateInput,
    },
    types::{
        InstanceSettingsPayload, UpdateAuthenticationSettingsInput, UpdateProtocolSettingsInput,
    },
};
use crate::graphql::schema::{
    access::access, authorization::request_context, error::app_error,
    management_guard::ManagementGuard, modules::resource::support::request_authority,
};

#[derive(Default)]
pub(crate) struct SettingMutation;

#[Object]
impl SettingMutation {
    /// Replace the instance-wide OAuth and OpenID Connect protocol defaults.
    #[graphql(
        guard = "ManagementGuard::new(ManagementScope::SettingsWrite, ManagementTarget::instance())",
        directive = access::apply(ManagementGuard::policy(ManagementScope::SettingsWrite))
    )]
    async fn update_protocol_settings(
        &self,
        ctx: &Context<'_>,
        input: UpdateProtocolSettingsInput,
    ) -> Result<InstanceSettingsPayload> {
        let request = request_context(ctx)?;
        let client_mutation_id = input.client_mutation_id.clone();
        let result = async {
            let authority = request_authority(request).await?;
            request
                .state
                .services()
                .instance_setting()
                .update_protocol(
                    &authority,
                    UpdateProtocolSettingsCommand {
                        oauth_version: input.oauth_version.into(),
                        require_pushed_authorization_requests: input
                            .require_pushed_authorization_requests,
                        pushed_authorization_request_lifetime_seconds: i64::from(
                            input.pushed_authorization_request_lifetime_seconds,
                        ),
                        device_authorization_request_lifetime_seconds: i64::from(
                            input.device_authorization_request_lifetime_seconds,
                        ),
                        device_authorization_polling_interval_seconds: i64::from(
                            input.device_authorization_polling_interval_seconds,
                        ),
                        dynamic_registration_enabled: input.dynamic_registration_enabled,
                        expected_version: input.expected_version,
                        client_mutation_id: input.client_mutation_id,
                    },
                )
                .await
        }
        .await
        .map_err(|error| app_error(ctx, error))?;
        Ok(InstanceSettingsPayload::new(result, client_mutation_id))
    }

    /// Replace the password policy and the password hashing cost. New hashing
    /// parameters apply as users next set or sign in with their password.
    #[graphql(
        guard = "ManagementGuard::new(ManagementScope::SettingsWrite, ManagementTarget::instance())",
        directive = access::apply(ManagementGuard::policy(ManagementScope::SettingsWrite))
    )]
    async fn update_authentication_settings(
        &self,
        ctx: &Context<'_>,
        input: UpdateAuthenticationSettingsInput,
    ) -> Result<InstanceSettingsPayload> {
        let request = request_context(ctx)?;
        let client_mutation_id = input.client_mutation_id.clone();
        let hashing = input.password_hashing;
        let result = async {
            let authority = request_authority(request).await?;
            request
                .state
                .services()
                .instance_setting()
                .update_authentication(
                    &authority,
                    UpdateAuthenticationSettingsCommand {
                        breached_password_check_enabled: input.breached_password_check_enabled,
                        identifier_enumeration_allowed: input.identifier_enumeration_allowed,
                        email_sign_in_enabled: input.email_sign_in_enabled,
                        password_reset_enabled: input.password_reset_enabled,
                        registration_enabled: input.registration_enabled,
                        password_max_age_days: input.password_max_age_days,
                        password_history_count: input.password_history_count,
                        password_hashing: PasswordHashingView {
                            time_cost: hashing.time_cost,
                            memory_cost_kib: hashing.memory_cost_kib,
                            parallelism: hashing.parallelism,
                        },
                        expected_version: input.expected_version,
                        client_mutation_id: input.client_mutation_id,
                    },
                )
                .await
        }
        .await
        .map_err(|error| app_error(ctx, error))?;
        Ok(InstanceSettingsPayload::new(result, client_mutation_id))
    }

    /// Replace how email is sent. Secrets left out keep their stored value
    /// while the authentication method stays the same.
    #[graphql(
        guard = "ManagementGuard::new(ManagementScope::SettingsWrite, ManagementTarget::instance())",
        directive = access::apply(ManagementGuard::policy(ManagementScope::SettingsWrite))
    )]
    async fn update_email_delivery_settings(
        &self,
        ctx: &Context<'_>,
        input: UpdateEmailDeliverySettingsInput,
    ) -> Result<InstanceSettingsPayload> {
        let request = request_context(ctx)?;
        let client_mutation_id = input.client_mutation_id.clone();
        let result = async {
            let authority = request_authority(request).await?;
            request
                .state
                .services()
                .instance_setting()
                .update_email_delivery(
                    &authority,
                    UpdateEmailDeliveryCommand {
                        enabled: input.enabled,
                        host: input.host,
                        port: i64::from(input.port),
                        security: input.security.into(),
                        sender_address: input.sender_address,
                        sender_name: input.sender_name,
                        authentication: input.authentication.into(),
                        expected_version: input.expected_version,
                        client_mutation_id: input.client_mutation_id,
                    },
                )
                .await
        }
        .await
        .map_err(|error| app_error(ctx, error))?;
        Ok(InstanceSettingsPayload::new(result, client_mutation_id))
    }

    /// Replace one email template in the given locales; every other locale
    /// uses its built-in template. Each template is rendered with sample
    /// values before it is saved.
    #[graphql(
        guard = "ManagementGuard::new(ManagementScope::SettingsWrite, ManagementTarget::instance())",
        directive = access::apply(ManagementGuard::policy(ManagementScope::SettingsWrite))
    )]
    async fn update_email_template(
        &self,
        ctx: &Context<'_>,
        input: UpdateEmailTemplateInput,
    ) -> Result<InstanceSettingsPayload> {
        let request = request_context(ctx)?;
        let client_mutation_id = input.client_mutation_id.clone();
        let result = async {
            let authority = request_authority(request).await?;
            request
                .state
                .services()
                .instance_setting()
                .update_email_template(
                    &authority,
                    UpdateEmailTemplateCommand {
                        kind: input.kind.into(),
                        template: input.content.map(Into::into),
                        expected_version: input.expected_version,
                        client_mutation_id: input.client_mutation_id,
                    },
                )
                .await
        }
        .await
        .map_err(|error| app_error(ctx, error))?;
        Ok(InstanceSettingsPayload::new(result, client_mutation_id))
    }

    /// Send a short message with the stored delivery settings.
    #[graphql(
        guard = "ManagementGuard::new(ManagementScope::SettingsWrite, ManagementTarget::instance())",
        directive = access::apply(ManagementGuard::policy(ManagementScope::SettingsWrite))
    )]
    async fn send_test_email(
        &self,
        ctx: &Context<'_>,
        input: SendTestEmailInput,
    ) -> Result<SendTestEmailPayload> {
        let request = request_context(ctx)?;
        request
            .state
            .services()
            .instance_setting()
            .send_test_email(SendTestEmailCommand {
                recipient: input.recipient,
                locale: input.locale,
                template: input.template.map(|template| SendTestEmailTemplate {
                    kind: template.kind.into(),
                    locale: template.locale,
                    content: template.content.into(),
                }),
            })
            .await
            .map_err(|error| app_error(ctx, error))?;
        Ok(SendTestEmailPayload {
            sent: true,
            client_mutation_id: input.client_mutation_id,
        })
    }
}
