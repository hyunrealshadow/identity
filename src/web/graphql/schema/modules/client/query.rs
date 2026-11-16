use crate::graphql::schema::access::access;
use async_graphql::{
    Context, ID, Object, Result, SimpleObject,
    connection::{Connection, Edge},
};
use identity_application::authorization::ManagementTarget;
use identity_domain::authorization::ManagementScope;

use super::{
    integration,
    types::{ClientFilter, ClientNode, ClientOrder, decode_client_oid},
};
use crate::graphql::schema::{
    authorization::request_context,
    connection,
    connection::ConnectionTotal,
    error::app_error,
    management_guard::ManagementGuard,
    modules::resource::support::{RbacConnectionCursor, page_args},
};

#[derive(Default)]
pub(crate) struct ClientQuery;

#[Object]
impl ClientQuery {
    #[graphql(
        guard = "ManagementGuard::new(ManagementScope::ClientsRead, ManagementTarget::instance())",
        directive = access::apply(ManagementGuard::policy(ManagementScope::ClientsRead))
    )]
    async fn client(&self, ctx: &Context<'_>, id: ID) -> Result<Option<ClientNode>> {
        let oid = decode_client_oid(ctx, &id)?;
        let record = integration::find_client(request_context(ctx)?, oid)
            .await
            .map_err(|error| app_error(ctx, error))?;
        Ok(record.map(ClientNode::new))
    }

    #[graphql(
        guard = "ManagementGuard::new(ManagementScope::ClientsRead, ManagementTarget::instance())",
        directive = access::apply(ManagementGuard::policy(ManagementScope::ClientsRead)),
        complexity = "1 + first.or(last).unwrap_or(20).clamp(1, 100) as usize * child_complexity"
    )]
    #[allow(clippy::too_many_arguments)]
    async fn clients(
        &self,
        ctx: &Context<'_>,
        filter: Option<ClientFilter>,
        order_by: Option<ClientOrder>,
        #[graphql(validator(minimum = 1, maximum = 100))] first: Option<i32>,
        after: Option<String>,
        #[graphql(validator(minimum = 1, maximum = 100))] last: Option<i32>,
        before: Option<String>,
    ) -> Result<Connection<RbacConnectionCursor, ClientNode, ConnectionTotal>> {
        let page = page_args(ctx, first, after, last, before)?;
        let request = request_context(ctx)?;
        let filter = filter.unwrap_or_default();
        let page = integration::list_clients(
            request,
            filter.clone().into(),
            order_by.unwrap_or(ClientOrder::CreatedAtDesc).into(),
            page,
        )
        .await
        .map_err(|error| app_error(ctx, error))?;
        let additional = connection::connection_total(ctx, async {
            integration::count_clients(request, filter.into())
                .await
                .map_err(|error| app_error(ctx, error))
        })
        .await?;
        let mut connection = Connection::with_additional_fields(
            page.has_previous_page,
            page.has_next_page,
            additional,
        );
        connection.edges.extend(page.items.into_iter().map(|item| {
            Edge::new(
                RbacConnectionCursor::from_backend(item.cursor),
                ClientNode::new(item.record),
            )
        }));
        Ok(connection)
    }

    /// Values a client may register in its advanced settings: everything the
    /// provider supports, whether or not a key for it is active now. Each
    /// issuance uses the first listed algorithm with an active key.
    #[graphql(
        guard = "ManagementGuard::new(ManagementScope::ClientsRead, ManagementTarget::instance())",
        directive = access::apply(ManagementGuard::policy(ManagementScope::ClientsRead))
    )]
    async fn client_metadata_options(&self, ctx: &Context<'_>) -> Result<ClientMetadataOptions> {
        let provider = request_context(ctx)?.state.services().oidc();
        let options = provider.client_metadata_options();
        let active = provider
            .active_key_algorithms()
            .await
            .map_err(|error| app_error(ctx, error))?;
        Ok(ClientMetadataOptions {
            subject_types: options.subject_types,
            acr_values: options.acr_values.iter().map(ToString::to_string).collect(),
            id_token_signing_algs: options.id_token_signing_algs,
            id_token_encryption_algs: options.id_token_encryption_algs,
            id_token_encryption_encs: options.id_token_encryption_encs,
            userinfo_signing_algs: options.userinfo_signing_algs,
            userinfo_encryption_algs: options.userinfo_encryption_algs,
            userinfo_encryption_encs: options.userinfo_encryption_encs,
            request_object_signing_algs: options.request_object_signing_algs,
            request_object_encryption_algs: options.request_object_encryption_algs,
            request_object_encryption_encs: options.request_object_encryption_encs,
            token_endpoint_auth_signing_algs: options.token_endpoint_auth_signing_algs,
            active_signing_algs: active.signing,
            active_request_object_encryption_algs: active.request_object_encryption,
        })
    }
}

/// Supported values for the advanced client settings.
#[derive(SimpleObject)]
pub(crate) struct ClientMetadataOptions {
    subject_types: Vec<String>,
    acr_values: Vec<String>,
    id_token_signing_algs: Vec<String>,
    id_token_encryption_algs: Vec<String>,
    id_token_encryption_encs: Vec<String>,
    userinfo_signing_algs: Vec<String>,
    userinfo_encryption_algs: Vec<String>,
    userinfo_encryption_encs: Vec<String>,
    request_object_signing_algs: Vec<String>,
    request_object_encryption_algs: Vec<String>,
    request_object_encryption_encs: Vec<String>,
    token_endpoint_auth_signing_algs: Vec<String>,
    /// Provider signing algorithms (ID Token, UserInfo) with an active key
    /// now. Keys can be revoked at any time, so settings may list others; an
    /// issuance skips listed algorithms without a key.
    active_signing_algs: Vec<String>,
    /// Request object encryption algorithms with an active decryption key now.
    active_request_object_encryption_algs: Vec<String>,
}
