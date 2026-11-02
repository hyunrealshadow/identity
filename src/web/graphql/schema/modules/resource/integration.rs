//! Single GraphQL-to-application seam for API resource management.
//!
//! Reads carry no authority: the field Guard already established the read
//! scope. Every write passes the immutable request authority; the application
//! service and repository re-check the live binding/grant and owner facts.

use identity_application::{
    error::AppError,
    rbac::{
        ApiResourceRecord, CreateResourceCommand, ResourceFilter,
        ResourceOrder as ApplicationOrder, ResourcePage, ResourcePageRequest, ResourceStateCommand,
        UpdateResourceCommand,
    },
};
use identity_domain::rbac::ResourceOid;

use super::support::{PageArgs, request_authority};
use crate::graphql::schema::RequestContext;

pub(crate) async fn find_resource(
    request: &RequestContext,
    oid: ResourceOid,
) -> Result<Option<ApiResourceRecord>, AppError> {
    request
        .state
        .services()
        .rbac_management()
        .find_resource(oid)
        .await
}

pub(crate) async fn list_resources(
    request: &RequestContext,
    filter: ResourceFilter,
    order: ApplicationOrder,
    page: PageArgs,
) -> Result<ResourcePage, AppError> {
    request
        .state
        .services()
        .rbac_management()
        .list_resources(ResourcePageRequest {
            filter,
            order,
            first: page.first,
            after: page.after,
            last: page.last,
            before: page.before,
        })
        .await
}

pub(crate) async fn create_resource(
    request: &RequestContext,
    command: CreateResourceCommand,
) -> Result<ApiResourceRecord, AppError> {
    let authority = request_authority(request).await?;
    request
        .state
        .services()
        .rbac_management()
        .create_resource(&authority, command)
        .await
}

pub(crate) async fn update_resource(
    request: &RequestContext,
    command: UpdateResourceCommand,
) -> Result<ApiResourceRecord, AppError> {
    let authority = request_authority(request).await?;
    request
        .state
        .services()
        .rbac_management()
        .update_resource(&authority, command)
        .await
}

pub(crate) async fn enable_resource(
    request: &RequestContext,
    command: ResourceStateCommand,
) -> Result<ApiResourceRecord, AppError> {
    let authority = request_authority(request).await?;
    request
        .state
        .services()
        .rbac_management()
        .enable_resource(&authority, command)
        .await
}

pub(crate) async fn disable_resource(
    request: &RequestContext,
    command: ResourceStateCommand,
) -> Result<ApiResourceRecord, AppError> {
    let authority = request_authority(request).await?;
    request
        .state
        .services()
        .rbac_management()
        .disable_resource(&authority, command)
        .await
}
