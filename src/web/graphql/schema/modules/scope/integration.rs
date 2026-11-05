//! GraphQL-to-application seam for the global scope catalog and the narrow
//! `client_scope` delegation relation.

use identity_application::{
    error::AppError,
    rbac::{
        ClientScopePage, ClientScopePageRequest, ClientScopeSetResult, CreateScopeCommand,
        ScopeFilter, ScopeOid, ScopeOrder as ApplicationScopeOrder, ScopePage, ScopePageRequest,
        ScopeRecord, ScopeStateCommand, SetClientScopesCommand, UpdateScopeCommand,
    },
};
use identity_domain::client::model::ClientOid;

use super::super::resource::support::{PageArgs, request_authority};
use crate::graphql::schema::RequestContext;

pub(crate) async fn find_scope(
    request: &RequestContext,
    oid: ScopeOid,
) -> Result<Option<ScopeRecord>, AppError> {
    request
        .state
        .services()
        .rbac_management()
        .find_scope(oid)
        .await
}

pub(crate) async fn list_scopes(
    request: &RequestContext,
    filter: ScopeFilter,
    order: ApplicationScopeOrder,
    page: PageArgs,
) -> Result<ScopePage, AppError> {
    request
        .state
        .services()
        .rbac_management()
        .list_scopes(ScopePageRequest {
            filter,
            order,
            first: page.first,
            after: page.after,
            last: page.last,
            before: page.before,
        })
        .await
}

pub(crate) async fn create_scope(
    request: &RequestContext,
    command: CreateScopeCommand,
) -> Result<ScopeRecord, AppError> {
    let authority = request_authority(request).await?;
    request
        .state
        .services()
        .rbac_management()
        .create_scope(&authority, command)
        .await
}

pub(crate) async fn update_scope(
    request: &RequestContext,
    command: UpdateScopeCommand,
) -> Result<ScopeRecord, AppError> {
    let authority = request_authority(request).await?;
    request
        .state
        .services()
        .rbac_management()
        .update_scope(&authority, command)
        .await
}

pub(crate) async fn enable_scope(
    request: &RequestContext,
    command: ScopeStateCommand,
) -> Result<ScopeRecord, AppError> {
    let authority = request_authority(request).await?;
    request
        .state
        .services()
        .rbac_management()
        .enable_scope(&authority, command)
        .await
}

pub(crate) async fn disable_scope(
    request: &RequestContext,
    command: ScopeStateCommand,
) -> Result<ScopeRecord, AppError> {
    let authority = request_authority(request).await?;
    request
        .state
        .services()
        .rbac_management()
        .disable_scope(&authority, command)
        .await
}

pub(crate) async fn list_client_scopes(
    request: &RequestContext,
    client_oid: ClientOid,
    order: ApplicationScopeOrder,
    page: PageArgs,
) -> Result<ClientScopePage, AppError> {
    request
        .state
        .services()
        .rbac_management()
        .list_client_scopes(ClientScopePageRequest {
            client_oid,
            order,
            first: page.first,
            after: page.after,
            last: page.last,
            before: page.before,
        })
        .await
}

pub(crate) async fn set_client_scopes(
    request: &RequestContext,
    command: SetClientScopesCommand,
) -> Result<ClientScopeSetResult, AppError> {
    let authority = request_authority(request).await?;
    request
        .state
        .services()
        .rbac_management()
        .set_client_scopes(&authority, command)
        .await
}
