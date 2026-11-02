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
}

#[derive(SimpleObject)]
pub(crate) struct InstanceInfo {
    name: String,
    environment: String,
    issuer: String,
    version: String,
}
