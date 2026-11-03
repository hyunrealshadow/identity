//! Single integration seam for the user-management application use cases.
//!
//! The GraphQL adapter deliberately does not talk to repositories. Every call
//! here goes through `AppServices::user_management()` and passes the immutable
//! request authority (actor, exact token management scopes, management
//! snapshot, issuing client and its original derived fingerprint) built from
//! the transport-validated `RequestContext`. The application service remains
//! responsible for rechecking the authoritative binding/grant, issuing client,
//! target owner state, row locks and transaction/audit policy.
//!
//! Read methods intentionally carry no authority: the root field/native guard
//! already established `management.user.read`, and the service does not emit
//! fake audit facts for reads.

use identity_application::{
    error::AppError,
    user::management::{
        CreateUserCommand, UpdateUserCommand, UserFilter as ManagementFilter,
        UserManagementAuthority, UserManagementMutationResult, UserOrder as ManagementOrder,
        UserPageRequest, UserPassword, UserProfilePatch, UserStateCommand,
    },
};
use identity_domain::user::{User, UserOid};

use super::{
    super::resource::support,
    types::{UserFilter, UserOrder},
};
use crate::graphql::schema::RequestContext;

pub(super) struct UserPage {
    pub items: Vec<UserPageItem>,
    pub has_previous_page: bool,
    pub has_next_page: bool,
}

pub(super) struct UserPageItem {
    pub user: User,
    pub cursor: String,
}

async fn authority(request: &RequestContext) -> Result<UserManagementAuthority, AppError> {
    let authority = support::request_authority(request).await?;
    Ok(UserManagementAuthority::new(
        authority.actor,
        authority.token_scopes,
        authority.snapshot,
        authority.client_oid,
        authority.client_policy_version,
    ))
}

fn record_parts(record: UserManagementMutationResult) -> User {
    record.user
}

pub(crate) async fn find_user(
    request: &RequestContext,
    user: UserOid,
) -> Result<Option<User>, AppError> {
    let record = request
        .state
        .services()
        .user_management()
        .find_user(user)
        .await?;
    Ok(record.map(|record| record.user))
}

fn management_filter(filter: UserFilter) -> ManagementFilter {
    ManagementFilter {
        query: filter.query,
        username: filter.username,
        email: filter.email,
        enabled: filter.enabled,
        locked: filter.locked,
        created_from: filter.created_from,
        created_before: filter.created_before,
    }
}

pub(super) async fn count_users(
    request: &RequestContext,
    filter: UserFilter,
) -> Result<u64, AppError> {
    request
        .state
        .services()
        .user_management()
        .count_users(management_filter(filter))
        .await
}

pub(super) async fn list_users(
    request: &RequestContext,
    filter: UserFilter,
    order: UserOrder,
    first: Option<u32>,
    after: Option<String>,
    last: Option<u32>,
    before: Option<String>,
) -> Result<UserPage, AppError> {
    let page = request
        .state
        .services()
        .user_management()
        .list_users(UserPageRequest {
            filter: management_filter(filter),
            order: match order {
                UserOrder::CreatedAtAsc => ManagementOrder::CreatedAtAsc,
                UserOrder::CreatedAtDesc => ManagementOrder::CreatedAtDesc,
                UserOrder::UsernameAsc => ManagementOrder::UsernameAsc,
                UserOrder::UsernameDesc => ManagementOrder::UsernameDesc,
            },
            first,
            after,
            last,
            before,
        })
        .await?;
    Ok(UserPage {
        items: page
            .items
            .into_iter()
            .map(|item| UserPageItem {
                user: item.record.user,
                cursor: item.cursor,
            })
            .collect(),
        has_previous_page: page.has_previous_page,
        has_next_page: page.has_next_page,
    })
}

pub(super) async fn create_user(
    request: &RequestContext,
    username: String,
    email: String,
    password: String,
    profile: UserProfilePatch,
    reason: String,
    client_mutation_id: Option<String>,
) -> Result<User, AppError> {
    let authority = authority(request).await?;
    let record = request
        .state
        .services()
        .user_management()
        .create_user(
            &authority,
            CreateUserCommand {
                username,
                email,
                password: UserPassword::new(password),
                profile,
                reason,
                client_mutation_id,
            },
        )
        .await?;
    Ok(record_parts(record))
}

pub(super) async fn update_user(
    request: &RequestContext,
    command: UpdateUserCommand,
) -> Result<User, AppError> {
    let authority = authority(request).await?;
    let record = request
        .state
        .services()
        .user_management()
        .update_user(&authority, command)
        .await?;
    Ok(record_parts(record))
}

pub(super) async fn enable_user(
    request: &RequestContext,
    user: UserOid,
    expected_version: uuid::Uuid,
    reason: String,
    client_mutation_id: Option<String>,
) -> Result<User, AppError> {
    let authority = authority(request).await?;
    let record = request
        .state
        .services()
        .user_management()
        .enable_user(
            &authority,
            UserStateCommand {
                user_oid: user,
                expected_version,
                reason,
                client_mutation_id,
            },
        )
        .await?;
    Ok(record_parts(record))
}

pub(super) async fn disable_user(
    request: &RequestContext,
    user: UserOid,
    expected_version: uuid::Uuid,
    reason: String,
    client_mutation_id: Option<String>,
) -> Result<User, AppError> {
    let authority = authority(request).await?;
    let record = request
        .state
        .services()
        .user_management()
        .disable_user(
            &authority,
            UserStateCommand {
                user_oid: user,
                expected_version,
                reason,
                client_mutation_id,
            },
        )
        .await?;
    Ok(record_parts(record))
}

pub(super) async fn unlock_user(
    request: &RequestContext,
    user: UserOid,
    expected_version: uuid::Uuid,
    reason: String,
    client_mutation_id: Option<String>,
) -> Result<User, AppError> {
    let authority = authority(request).await?;
    let record = request
        .state
        .services()
        .user_management()
        .unlock_user(
            &authority,
            UserStateCommand {
                user_oid: user,
                expected_version,
                reason,
                client_mutation_id,
            },
        )
        .await?;
    Ok(record_parts(record))
}
