//! GraphQL-to-application seam for user groups.

use identity_application::{
    error::AppError,
    rbac::{
        AddGroupMemberCommand, CreateGroupCommand, DeleteGroupCommand, DeleteGroupResult,
        GroupFilter, GroupMembershipMutationResult, GroupMembershipPage,
        GroupMembershipPageRequest, GroupOrder as ApplicationGroupOrder, GroupPage,
        GroupPageRequest, GroupRecord, GroupRoleMutationResult, GroupRolePage,
        GroupRolePageRequest, GroupStateCommand, RemoveGroupMemberCommand, SetGroupRolesCommand,
        UpdateGroupCommand,
    },
};
use identity_domain::rbac::GroupOid;

use super::super::resource::support::{PageArgs, request_authority};
use crate::graphql::schema::RequestContext;

pub(crate) async fn find_group(
    request: &RequestContext,
    oid: GroupOid,
) -> Result<Option<GroupRecord>, AppError> {
    request
        .state
        .services()
        .group_management()
        .find_group(oid)
        .await
}

pub(crate) async fn list_groups(
    request: &RequestContext,
    filter: GroupFilter,
    order: ApplicationGroupOrder,
    page: PageArgs,
) -> Result<GroupPage, AppError> {
    request
        .state
        .services()
        .group_management()
        .list_groups(GroupPageRequest {
            filter,
            order,
            first: page.first,
            after: page.after,
            last: page.last,
            before: page.before,
        })
        .await
}

pub(crate) async fn list_group_memberships(
    request: &RequestContext,
    group_oid: GroupOid,
    page_request: GroupMembershipPageRequest,
) -> Result<GroupMembershipPage, AppError> {
    request
        .state
        .services()
        .group_management()
        .list_group_memberships(group_oid, page_request)
        .await
}

pub(crate) async fn list_group_roles(
    request: &RequestContext,
    group_oid: GroupOid,
    page_request: GroupRolePageRequest,
) -> Result<GroupRolePage, AppError> {
    request
        .state
        .services()
        .group_management()
        .list_group_roles(group_oid, page_request)
        .await
}

pub(crate) async fn create_group(
    request: &RequestContext,
    command: CreateGroupCommand,
) -> Result<GroupRecord, AppError> {
    let authority = request_authority(request).await?;
    request
        .state
        .services()
        .group_management()
        .create_group(&authority, command)
        .await
}

pub(crate) async fn update_group(
    request: &RequestContext,
    command: UpdateGroupCommand,
) -> Result<GroupRecord, AppError> {
    let authority = request_authority(request).await?;
    request
        .state
        .services()
        .group_management()
        .update_group(&authority, command)
        .await
}

pub(crate) async fn enable_group(
    request: &RequestContext,
    command: GroupStateCommand,
) -> Result<GroupRecord, AppError> {
    let authority = request_authority(request).await?;
    request
        .state
        .services()
        .group_management()
        .enable_group(&authority, command)
        .await
}

pub(crate) async fn disable_group(
    request: &RequestContext,
    command: GroupStateCommand,
) -> Result<GroupRecord, AppError> {
    let authority = request_authority(request).await?;
    request
        .state
        .services()
        .group_management()
        .disable_group(&authority, command)
        .await
}

pub(crate) async fn delete_group(
    request: &RequestContext,
    command: DeleteGroupCommand,
) -> Result<DeleteGroupResult, AppError> {
    let authority = request_authority(request).await?;
    request
        .state
        .services()
        .group_management()
        .delete_group(&authority, command)
        .await
}

pub(crate) async fn add_group_member(
    request: &RequestContext,
    command: AddGroupMemberCommand,
) -> Result<GroupMembershipMutationResult, AppError> {
    let authority = request_authority(request).await?;
    request
        .state
        .services()
        .group_management()
        .add_group_member(&authority, command)
        .await
}

pub(crate) async fn remove_group_member(
    request: &RequestContext,
    command: RemoveGroupMemberCommand,
) -> Result<GroupMembershipMutationResult, AppError> {
    let authority = request_authority(request).await?;
    request
        .state
        .services()
        .group_management()
        .remove_group_member(&authority, command)
        .await
}

pub(crate) async fn set_group_roles(
    request: &RequestContext,
    command: SetGroupRolesCommand,
) -> Result<GroupRoleMutationResult, AppError> {
    let authority = request_authority(request).await?;
    request
        .state
        .services()
        .group_management()
        .set_group_roles(&authority, command)
        .await
}
