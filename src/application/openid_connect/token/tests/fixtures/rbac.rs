//! Canonical business-resource fixtures for token tests.
//!
//! Protocol scopes are global (`resource_id IS NULL`). Custom API scopes belong
//! to exactly one resource. A client ceiling is expressed per resource, so a
//! code in another resource never authorizes the target audience. RBAC state is
//! built from the same canonical scope rows a real repository would project.

use std::{collections::BTreeSet, sync::Arc};

use chrono::Utc;
use identity_domain::{
    authorization::ids::AuthorizationVersion,
    client::model::ClientOid,
    client_authorization::{
        AccessTokenPrincipal, AuthorizationSnapshotData, BusinessAuthorizationSnapshotData,
    },
    openid_connect::resource::{
        OAuthResource, OAuthResourceRepository, OAuthResourceRepositoryError,
    },
    rbac::{
        BusinessAuthorizationSnapshot, RbacAuthorizationError, RbacAuthorizationRepository,
        RbacAuthorizationState, RbacResourceState, ResourceOid, ResourcePermission,
        ResourcePermissionOid, Role, RoleAuthorizationSnapshot, RoleOid, RolePermission,
        RolePermissionOid, STANDARD_OIDC_SCOPES, UserRole, UserRoleOid, UserRoleSnapshot,
        validate_business_snapshot,
    },
    user::UserOid,
};

/// Resource catalog plus exact per-resource client ceilings.
pub(in crate::openid_connect) struct TestOAuthResources {
    resources: Vec<OAuthResource>,
    /// `(client, resource, scopes, granted to the client itself)`.
    client_scopes: Vec<(ClientOid, String, Vec<String>, bool)>,
}

impl TestOAuthResources {
    pub(in crate::openid_connect) fn new(resources: Vec<OAuthResource>) -> Self {
        Self {
            resources,
            client_scopes: Vec::new(),
        }
    }

    pub(in crate::openid_connect) fn with_client_ceiling(
        self,
        client: ClientOid,
        resource_uri: &str,
        scopes: &[&str],
    ) -> Self {
        self.push_ceiling(client, resource_uri, scopes, true)
    }

    /// Rows that bound user-delegated requests but are not granted to the
    /// client itself.
    pub(in crate::openid_connect) fn with_delegated_client_ceiling(
        self,
        client: ClientOid,
        resource_uri: &str,
        scopes: &[&str],
    ) -> Self {
        self.push_ceiling(client, resource_uri, scopes, false)
    }

    fn push_ceiling(
        mut self,
        client: ClientOid,
        resource_uri: &str,
        scopes: &[&str],
        client_granted: bool,
    ) -> Self {
        self.client_scopes.push((
            client,
            resource_uri.to_owned(),
            scopes.iter().map(|scope| (*scope).to_owned()).collect(),
            client_granted,
        ));
        self
    }
}

#[async_trait::async_trait]
impl OAuthResourceRepository for TestOAuthResources {
    async fn find_by_uri(
        &self,
        uri: &str,
    ) -> Result<Option<OAuthResource>, OAuthResourceRepositoryError> {
        Ok(self
            .resources
            .iter()
            .find(|resource| resource.uri == uri)
            .cloned())
    }

    async fn client_scope_codes(
        &self,
        client: ClientOid,
        resource_uri: &str,
        principal: AccessTokenPrincipal,
    ) -> Result<Option<Vec<String>>, OAuthResourceRepositoryError> {
        let mut rows = self
            .client_scopes
            .iter()
            .filter(|(candidate, uri, _, _)| *candidate == client && uri.as_str() == resource_uri)
            .peekable();
        if rows.peek().is_none() {
            return Ok(None);
        }
        Ok(Some(
            rows.filter(|(_, _, _, granted)| *granted || principal == AccessTokenPrincipal::User)
                .flat_map(|(_, _, scopes, _)| scopes.iter().cloned())
                .collect(),
        ))
    }

    async fn client_protocol_scope_codes(
        &self,
        client: ClientOid,
    ) -> Result<Option<Vec<String>>, OAuthResourceRepositoryError> {
        let mut protocol = BTreeSet::new();
        for (candidate, _, scopes, _) in &self.client_scopes {
            if *candidate == client {
                protocol.extend(
                    scopes
                        .iter()
                        .filter(|scope| STANDARD_OIDC_SCOPES.contains(&scope.as_str()))
                        .cloned(),
                );
            }
        }
        Ok(Some(protocol.into_iter().collect()))
    }
}

/// In-memory authoritative RBAC state. `validate_snapshot` performs the same
/// exact snapshot check as the database adapter, so stale or forged fixtures
/// cannot silently pass.
pub(in crate::openid_connect) struct TestRbacRepository {
    states: Vec<RbacAuthorizationState>,
}

impl TestRbacRepository {
    pub(in crate::openid_connect) fn new(states: Vec<RbacAuthorizationState>) -> Self {
        Self { states }
    }

    pub(in crate::openid_connect) fn shared(states: Vec<RbacAuthorizationState>) -> Arc<Self> {
        Arc::new(Self::new(states))
    }
}

#[async_trait::async_trait]
impl RbacAuthorizationRepository for TestRbacRepository {
    async fn resource_state(
        &self,
        resource_uri: &str,
    ) -> Result<RbacResourceState, RbacAuthorizationError> {
        self.states
            .iter()
            .find(|state| state.resource.resource_uri == resource_uri)
            .map(|state| state.resource.clone())
            .ok_or(RbacAuthorizationError::ResourceNotFound)
    }

    async fn authorization_state(
        &self,
        user: UserOid,
        resource_uri: &str,
    ) -> Result<RbacAuthorizationState, RbacAuthorizationError> {
        self.states
            .iter()
            .find(|state| {
                state.resource.resource_uri == resource_uri && state.user_oid == Some(user)
            })
            .cloned()
            .ok_or(RbacAuthorizationError::UserNotFound)
    }

    async fn validate_snapshot(
        &self,
        snapshot: &BusinessAuthorizationSnapshot,
    ) -> Result<RbacAuthorizationState, RbacAuthorizationError> {
        let state = self
            .states
            .iter()
            .find(|state| {
                state.resource.resource_uri == snapshot.resource_uri
                    && state.user_oid == snapshot.user_oid
            })
            .ok_or(RbacAuthorizationError::ResourceNotFound)?;
        validate_business_snapshot(snapshot, state)?;
        Ok(state.clone())
    }

    async fn client_scope_codes(
        &self,
        _client: ClientOid,
        _resource_uri: &str,
    ) -> Result<BTreeSet<String>, RbacAuthorizationError> {
        Ok(BTreeSet::new())
    }
}

/// Build one enabled business resource whose canonical scope rows are exactly
/// `codes`. These are the only API scopes the resource can own.
pub(in crate::openid_connect) fn business_resource(uri: &str, codes: &[&str]) -> RbacResourceState {
    let now = Utc::now();
    let resource_oid = ResourceOid::new();
    let permissions = codes
        .iter()
        .map(|code| {
            ResourcePermission::new(ResourcePermissionOid::new(), resource_oid, *code, None, now)
                .expect("test permission code")
        })
        .collect::<Vec<_>>();
    RbacResourceState {
        resource_oid,
        resource_uri: uri.to_owned(),
        policy_version: AuthorizationVersion::new(),
        enabled: true,
        accepted_scopes: codes.iter().map(|code| (*code).to_owned()).collect(),
        permissions,
    }
}

/// Human state with one direct role granting every permission of `resource`.
pub(in crate::openid_connect) fn delegated_user_state(
    resource: &RbacResourceState,
    user: UserOid,
) -> RbacAuthorizationState {
    let now = Utc::now();
    let role = Role::new(RoleOid::new(), "Business reader", "", now).expect("test role");
    let binding = UserRole::new(UserRoleOid::new(), user, role.oid, None, "test grant", now)
        .expect("test binding");
    let memberships = resource
        .permissions
        .iter()
        .map(|permission| RolePermission {
            oid: RolePermissionOid::new(),
            role_oid: role.oid,
            permission_oid: permission.oid,
            created_at: now,
        })
        .collect();
    RbacAuthorizationState {
        resource: resource.clone(),
        user_oid: Some(user),
        user_authorization_version: Some(AuthorizationVersion::new()),
        user_enabled: Some(true),
        user_locked: Some(false),
        bindings: vec![binding],
        group_paths: Vec::new(),
        roles: vec![role],
        memberships,
    }
}

/// Snapshot data matching [`delegated_user_state`], suitable for a code or
/// refresh token. The exact binding and role identities are preserved.
pub(in crate::openid_connect) fn delegated_snapshot(
    state: &RbacAuthorizationState,
) -> AuthorizationSnapshotData {
    let snapshot = BusinessAuthorizationSnapshot::for_user(
        &state.resource,
        state.user_oid.expect("human state"),
        state
            .user_authorization_version
            .expect("human authorization version"),
        state
            .bindings
            .iter()
            .map(UserRoleSnapshot::from_binding)
            .collect(),
        state
            .roles
            .iter()
            .map(|role| RoleAuthorizationSnapshot { role_oid: role.oid })
            .collect(),
    );
    AuthorizationSnapshotData::Business(BusinessAuthorizationSnapshotData::from_snapshot(&snapshot))
}

/// OAuth resource projection for one of the canonical business resources.
pub(in crate::openid_connect) fn oauth_resource(uri: &str, codes: &[&str]) -> OAuthResource {
    OAuthResource {
        uri: uri.to_owned(),
        scopes: codes.iter().map(|code| (*code).to_owned()).collect(),
        enabled: true,
    }
}
