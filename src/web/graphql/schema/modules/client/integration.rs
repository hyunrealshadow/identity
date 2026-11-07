//! Single GraphQL-to-application seam for OAuth client management.
//!
//! Reads carry no authority: field guards already established the read scope.
//! Every write passes the immutable request authority; the repository re-checks
//! live authority inside its transaction.

use identity_application::{
    client::{
        AddClientJwksUriCommand, AddClientPublicKeyCommand, ClientCredentialRecord,
        ClientCredentialResult, ClientCredentialRevokeResult, ClientFilter, ClientOrder,
        ClientPage, ClientPageRequest, ClientRecord, ClientSecretResult, ClientStateCommand,
        CreateClientCommand, CreateClientSecretCommand, RevokeClientCredentialCommand,
        UpdateClientCommand,
    },
    error::AppError,
};
use identity_domain::client::model::ClientOid;

use super::super::resource::support::{PageArgs, request_authority};
use crate::graphql::schema::RequestContext;

pub(crate) async fn find_client(
    request: &RequestContext,
    oid: ClientOid,
) -> Result<Option<ClientRecord>, AppError> {
    request
        .state
        .services()
        .client_management()
        .find_client(oid)
        .await
}

pub(crate) async fn count_clients(
    request: &RequestContext,
    filter: ClientFilter,
) -> Result<u64, AppError> {
    request
        .state
        .services()
        .client_management()
        .count_clients(filter)
        .await
}

pub(crate) async fn list_clients(
    request: &RequestContext,
    filter: ClientFilter,
    order: ClientOrder,
    page: PageArgs,
) -> Result<ClientPage, AppError> {
    request
        .state
        .services()
        .client_management()
        .list_clients(ClientPageRequest {
            filter,
            order,
            first: page.first,
            after: page.after,
            last: page.last,
            before: page.before,
        })
        .await
}

pub(crate) async fn list_credentials(
    request: &RequestContext,
    oid: ClientOid,
) -> Result<Vec<ClientCredentialRecord>, AppError> {
    request
        .state
        .services()
        .client_management()
        .list_client_credentials(oid)
        .await
}

pub(crate) async fn create_client(
    request: &RequestContext,
    command: CreateClientCommand,
) -> Result<ClientRecord, AppError> {
    let authority = request_authority(request).await?;
    request
        .state
        .services()
        .client_management()
        .create_client(&authority, command)
        .await
}

pub(crate) async fn update_client(
    request: &RequestContext,
    command: UpdateClientCommand,
) -> Result<ClientRecord, AppError> {
    let authority = request_authority(request).await?;
    request
        .state
        .services()
        .client_management()
        .update_client(&authority, command)
        .await
}

pub(crate) async fn set_client_enabled(
    request: &RequestContext,
    command: ClientStateCommand,
    enabled: bool,
) -> Result<ClientRecord, AppError> {
    let authority = request_authority(request).await?;
    let service = request.state.services().client_management();
    if enabled {
        service.enable_client(&authority, command).await
    } else {
        service.disable_client(&authority, command).await
    }
}

pub(crate) async fn delete_client(
    request: &RequestContext,
    command: ClientStateCommand,
) -> Result<ClientOid, AppError> {
    let authority = request_authority(request).await?;
    request
        .state
        .services()
        .client_management()
        .delete_client(&authority, command)
        .await
}

pub(crate) async fn create_client_secret(
    request: &RequestContext,
    command: CreateClientSecretCommand,
) -> Result<ClientSecretResult, AppError> {
    let authority = request_authority(request).await?;
    request
        .state
        .services()
        .client_management()
        .create_client_secret(&authority, command)
        .await
}

pub(crate) async fn revoke_client_credential(
    request: &RequestContext,
    command: RevokeClientCredentialCommand,
) -> Result<ClientCredentialRevokeResult, AppError> {
    let authority = request_authority(request).await?;
    request
        .state
        .services()
        .client_management()
        .revoke_client_credential(&authority, command)
        .await
}

pub(crate) async fn add_client_public_key(
    request: &RequestContext,
    command: AddClientPublicKeyCommand,
) -> Result<ClientCredentialResult, AppError> {
    let authority = request_authority(request).await?;
    request
        .state
        .services()
        .client_management()
        .add_client_public_key(&authority, command)
        .await
}

pub(crate) async fn add_client_jwks_uri(
    request: &RequestContext,
    command: AddClientJwksUriCommand,
) -> Result<ClientCredentialResult, AppError> {
    let authority = request_authority(request).await?;
    request
        .state
        .services()
        .client_management()
        .add_client_jwks_uri(&authority, command)
        .await
}
