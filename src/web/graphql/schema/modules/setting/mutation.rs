use async_graphql::{Context, Object, Result};
use identity_application::{
    authorization::ManagementTarget,
    setting::management::{
        PasswordHashingView, UpdateAuthenticationSettingsCommand, UpdateProtocolSettingsCommand,
    },
};
use identity_domain::authorization::ManagementScope;

use super::types::{
    InstanceSettingsPayload, UpdateAuthenticationSettingsInput, UpdateProtocolSettingsInput,
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
}
