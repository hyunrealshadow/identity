//! GraphQL-to-application seam for business roles and user-role bindings.

use identity_application::{
    error::AppError,
    rbac::{
        AssignUserRolesCommand, CreateRoleCommand, EffectivePermissionPage,
        EffectivePermissionPageRequest, RevokeUserRolesCommand, RoleFilter,
        RoleOrder as ApplicationOrder, RolePage, RolePageRequest, RoleRecord, RoleStateCommand,
        RoleUserPageRequest, SetRolePermissionsCommand, UpdateRoleCommand, UserRoleMutationResult,
        UserRolePage, UserRolePageRequest,
    },
};
use identity_domain::rbac::RoleOid;

use super::super::resource::support::{PageArgs, request_authority};
use crate::graphql::schema::RequestContext;

pub(crate) async fn find_role(
    request: &RequestContext,
    oid: RoleOid,
) -> Result<Option<RoleRecord>, AppError> {
    request
        .state
        .services()
        .rbac_management()
        .find_role(oid)
        .await
}

pub(crate) async fn list_roles(
    request: &RequestContext,
    filter: RoleFilter,
    order: ApplicationOrder,
    page: PageArgs,
) -> Result<RolePage, AppError> {
    request
        .state
        .services()
        .rbac_management()
        .list_roles(RolePageRequest {
            filter,
            order,
            first: page.first,
            after: page.after,
            last: page.last,
            before: page.before,
        })
        .await
}

pub(crate) async fn create_role(
    request: &RequestContext,
    command: CreateRoleCommand,
) -> Result<RoleRecord, AppError> {
    let authority = request_authority(request).await?;
    request
        .state
        .services()
        .rbac_management()
        .create_role(&authority, command)
        .await
}

pub(crate) async fn update_role(
    request: &RequestContext,
    command: UpdateRoleCommand,
) -> Result<RoleRecord, AppError> {
    let authority = request_authority(request).await?;
    request
        .state
        .services()
        .rbac_management()
        .update_role(&authority, command)
        .await
}

pub(crate) async fn enable_role(
    request: &RequestContext,
    command: RoleStateCommand,
) -> Result<RoleRecord, AppError> {
    let authority = request_authority(request).await?;
    request
        .state
        .services()
        .rbac_management()
        .enable_role(&authority, command)
        .await
}

pub(crate) async fn disable_role(
    request: &RequestContext,
    command: RoleStateCommand,
) -> Result<RoleRecord, AppError> {
    let authority = request_authority(request).await?;
    request
        .state
        .services()
        .rbac_management()
        .disable_role(&authority, command)
        .await
}

pub(crate) async fn set_role_permissions(
    request: &RequestContext,
    command: SetRolePermissionsCommand,
) -> Result<RoleRecord, AppError> {
    let authority = request_authority(request).await?;
    request
        .state
        .services()
        .rbac_management()
        .set_role_permissions(&authority, command)
        .await
}

pub(crate) async fn list_user_roles(
    request: &RequestContext,
    request_page: UserRolePageRequest,
) -> Result<UserRolePage, AppError> {
    request
        .state
        .services()
        .rbac_management()
        .list_user_roles(request_page)
        .await
}

pub(crate) async fn list_role_users(
    request: &RequestContext,
    request_page: RoleUserPageRequest,
) -> Result<UserRolePage, AppError> {
    request
        .state
        .services()
        .rbac_management()
        .list_role_users(request_page)
        .await
}

/// Roles referenced by one page of relation edges.
pub(crate) async fn find_roles(
    request: &RequestContext,
    oids: Vec<RoleOid>,
) -> Result<Vec<RoleRecord>, AppError> {
    request
        .state
        .services()
        .rbac_management()
        .find_roles(oids)
        .await
}

pub(crate) async fn list_effective_permissions(
    request: &RequestContext,
    request_page: EffectivePermissionPageRequest,
) -> Result<EffectivePermissionPage, AppError> {
    request
        .state
        .services()
        .rbac_management()
        .list_user_permissions(request_page)
        .await
}

pub(crate) async fn assign_user_roles(
    request: &RequestContext,
    command: AssignUserRolesCommand,
) -> Result<UserRoleMutationResult, AppError> {
    let authority = request_authority(request).await?;
    request
        .state
        .services()
        .rbac_management()
        .assign_user_roles(&authority, command)
        .await
}

pub(crate) async fn revoke_user_roles(
    request: &RequestContext,
    command: RevokeUserRolesCommand,
) -> Result<UserRoleMutationResult, AppError> {
    let authority = request_authority(request).await?;
    request
        .state
        .services()
        .rbac_management()
        .revoke_user_roles(&authority, command)
        .await
}
