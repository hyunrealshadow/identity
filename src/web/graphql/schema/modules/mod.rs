use async_graphql::MergedObject;

use self::{
    account::{AccountMutation, AccountQuery},
    authorization::AuthorizationQuery,
    client::{ClientMutation, ClientQuery},
    group::{GroupMutation, GroupQuery},
    instance::InstanceQuery,
    node::NodeQuery,
    resource::{ResourceMutation, ResourceQuery},
    role::{RoleMutation, RoleQuery},
    scope::{ClientScopeMutation, ScopeMutation, ScopeQuery},
    security::{SecurityMutation, SecurityQuery},
    session::{SessionMutation, SessionQuery},
    user::{UserManagementMutation, UserManagementQuery},
};

pub(super) mod account;
mod authorization;
mod client;
mod group;
mod instance;
mod localized;
mod node;
mod relation;
mod resource;
mod role;
mod scope;
mod security;
mod session;
mod user;

/// Flat self-service and management query root. Each functional module
/// contributes its own business field; there is no `viewer` wrapper and no
/// `management` namespace.
#[derive(MergedObject, Default)]
pub(crate) struct QueryRoot(
    AccountQuery,
    SecurityQuery,
    SessionQuery,
    NodeQuery,
    InstanceQuery,
    AuthorizationQuery,
    GroupQuery,
    UserManagementQuery,
    ResourceQuery,
    ScopeQuery,
    RoleQuery,
    ClientQuery,
);

#[derive(MergedObject, Default)]
pub(crate) struct MutationRoot(
    AccountMutation,
    SecurityMutation,
    SessionMutation,
    UserManagementMutation,
    GroupMutation,
    ResourceMutation,
    ScopeMutation,
    RoleMutation,
    ClientMutation,
    ClientScopeMutation,
);
