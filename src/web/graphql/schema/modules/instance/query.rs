use crate::graphql::schema::access::{AccessPolicy, access};
use async_graphql::{Context, Object, Result, SimpleObject};
use chrono::Utc;
use identity_application::error::{codes::graphql::GraphqlErrorCode, params::ErrorParams};
use tracing::error;

use super::overview::InstanceOverview;
use crate::graphql::schema::{authorization::request_context, error::coded_error};

#[derive(Default)]
pub(crate) struct InstanceQuery;

#[Object]
impl InstanceQuery {
    /// Aggregate instance dashboard. The container itself is available to any
    /// authenticated principal and captures its timestamp once; each nested
    /// aggregate is guarded and loaded lazily.
    #[graphql(name = "instanceOverview", directive = access::apply(AccessPolicy::authenticated()))]
    async fn instance_overview(&self) -> InstanceOverview {
        InstanceOverview::new(Utc::now())
    }

    /// Safe public deployment metadata. No management scope is required, but
    /// the transport still requires a valid access token.
    #[graphql(directive = access::apply(AccessPolicy::authenticated()))]
    async fn instance_info(&self, ctx: &Context<'_>) -> Result<InstanceInfo> {
        let request = request_context(ctx)?;
        let issuer = request.state.services().oidc().issuer().map_err(|error| {
            error!(
                target: "identity.graphql",
                error = %error,
                "instance issuer metadata unavailable"
            );
            coded_error(
                ctx,
                GraphqlErrorCode::InstanceMetadataUnavailable,
                ErrorParams::new(),
            )
        })?;
        Ok(InstanceInfo {
            name: "Identity".to_owned(),
            environment: request.state.context().environment().as_str().to_owned(),
            issuer: issuer.to_string(),
            version: env!("CARGO_PKG_VERSION").to_owned(),
        })
    }
    /// Endpoint URLs an integrating application needs. This is the same public
    /// discovery data the well-known documents publish; the transport still
    /// requires a valid access token.
    #[graphql(name = "instanceMetadata", directive = access::apply(AccessPolicy::authenticated()))]
    async fn instance_metadata(&self, ctx: &Context<'_>) -> Result<InstanceMetadata> {
        let request = request_context(ctx)?;
        let provider = request.state.services().oidc();
        let metadata = provider.discovery_metadata().await.map_err(|error| {
            error!(
                target: "identity.graphql",
                error = %error,
                "instance endpoint metadata unavailable"
            );
            coded_error(
                ctx,
                GraphqlErrorCode::InstanceMetadataUnavailable,
                ErrorParams::new(),
            )
        })?;
        let (openid_configuration, oauth_authorization_server) =
            provider.well_known_urls().map_err(|error| {
                error!(
                    target: "identity.graphql",
                    error = %error,
                    "instance well-known metadata unavailable"
                );
                coded_error(
                    ctx,
                    GraphqlErrorCode::InstanceMetadataUnavailable,
                    ErrorParams::new(),
                )
            })?;
        let url = |value: &url::Url| value.to_string();
        let optional = |value: Option<&url::Url>| value.map(ToString::to_string);
        Ok(InstanceMetadata {
            issuer: url(&metadata.issuer),
            openid_configuration_url: url(&openid_configuration),
            oauth_authorization_server_metadata_url: url(&oauth_authorization_server),
            jwks_uri: url(&metadata.jwks_uri),
            authorization_endpoint: url(&metadata.authorization_endpoint),
            token_endpoint: optional(metadata.token_endpoint.as_ref()),
            pushed_authorization_request_endpoint: optional(
                metadata.pushed_authorization_request_endpoint.as_ref(),
            ),
            userinfo_endpoint: optional(metadata.userinfo_endpoint.as_ref()),
            device_authorization_endpoint: optional(
                metadata.device_authorization_endpoint.as_ref(),
            ),
            revocation_endpoint: url(&metadata.revocation_endpoint),
            introspection_endpoint: url(&metadata.introspection_endpoint),
            end_session_endpoint: optional(metadata.end_session_endpoint.as_ref()),
            check_session_iframe: optional(metadata.check_session_iframe.as_ref()),
            registration_endpoint: optional(metadata.registration_endpoint.as_ref()),
            service_documentation: optional(metadata.service_documentation.as_ref()),
            policy_uri: optional(metadata.op_policy_uri.as_ref()),
            terms_of_service_uri: optional(metadata.op_tos_uri.as_ref()),
        })
    }
}

/// Endpoint URLs published by this instance. Optional entries are absent when
/// the corresponding capability is not enabled.
#[derive(SimpleObject)]
pub(crate) struct InstanceMetadata {
    issuer: String,
    openid_configuration_url: String,
    oauth_authorization_server_metadata_url: String,
    jwks_uri: String,
    authorization_endpoint: String,
    token_endpoint: Option<String>,
    pushed_authorization_request_endpoint: Option<String>,
    userinfo_endpoint: Option<String>,
    device_authorization_endpoint: Option<String>,
    revocation_endpoint: String,
    introspection_endpoint: String,
    end_session_endpoint: Option<String>,
    check_session_iframe: Option<String>,
    registration_endpoint: Option<String>,
    service_documentation: Option<String>,
    policy_uri: Option<String>,
    terms_of_service_uri: Option<String>,
}

#[derive(SimpleObject)]
pub(crate) struct InstanceInfo {
    name: String,
    environment: String,
    issuer: String,
    version: String,
}
