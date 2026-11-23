use async_graphql::{Context, Object, Result};
use identity_application::authorization::ManagementTarget;
use identity_domain::authorization::ManagementScope;

use super::{
    email::{EmailTemplatePreview, EmailTemplatePreviewInput},
    types::InstanceSettings,
};
use crate::graphql::schema::{
    access::access, authorization::request_context, error::app_error,
    management_guard::ManagementGuard,
};

#[derive(Default)]
pub(crate) struct SettingQuery;

#[Object]
impl SettingQuery {
    /// Instance-wide settings as currently stored.
    #[graphql(
        guard = "ManagementGuard::new(ManagementScope::SettingsRead, ManagementTarget::instance())",
        directive = access::apply(ManagementGuard::policy(ManagementScope::SettingsRead))
    )]
    async fn instance_settings(&self, ctx: &Context<'_>) -> Result<Option<InstanceSettings>> {
        let view = request_context(ctx)?
            .state
            .services()
            .instance_setting()
            .read()
            .await
            .map_err(|error| app_error(ctx, error))?;
        Ok(Some(InstanceSettings::from(view)))
    }

    /// Render a draft email template with sample values, without saving it.
    #[graphql(
        guard = "ManagementGuard::new(ManagementScope::SettingsRead, ManagementTarget::instance())",
        directive = access::apply(ManagementGuard::policy(ManagementScope::SettingsRead))
    )]
    async fn email_template_preview(
        &self,
        ctx: &Context<'_>,
        input: EmailTemplatePreviewInput,
    ) -> Result<Option<EmailTemplatePreview>> {
        let rendered = request_context(ctx)?
            .state
            .services()
            .instance_setting()
            .preview_email_template(
                input.kind.into(),
                input.locale.as_deref(),
                &input.content.into(),
            )
            .map_err(|error| app_error(ctx, error))?;
        Ok(Some(rendered.into()))
    }
}
