//! Shared adapter support for the flat business-RBAC roots.
//!
//! Global IDs, audit reasons, and request authority construction are identical
//! for every RBAC functional module. Keeping them in one place prevents one
//! root from silently accepting a different shape or authority snapshot than
//! its siblings.

use std::{collections::BTreeSet, result::Result as StdResult};

use async_graphql::{Context, ID, Result};
use identity_application::{
    error::{
        AppError,
        codes::{authorization, graphql, rbac},
    },
    rbac::RbacManagementAuthority,
};
use identity_domain::{
    authorization::{ManagementScope, PolicyVersion},
    global_id::{GlobalId, GlobalIdType},
};
use uuid::Uuid;

use crate::graphql::schema::{RequestContext, error::app_error};

pub(crate) fn decode_oid<T: GlobalIdType>(ctx: &Context<'_>, id: &ID) -> Result<Uuid> {
    GlobalId::<T>::decode(id.as_str())
        .map(|id| id.oid())
        .map_err(|_| app_error(ctx, graphql::error::InvalidGlobalId))
}

pub(crate) fn decode_oids<T: GlobalIdType>(ctx: &Context<'_>, ids: &[ID]) -> Result<Vec<Uuid>> {
    ids.iter().map(|id| decode_oid::<T>(ctx, id)).collect()
}

/// Normalize an optional audit annotation and bound voluntarily supplied text.
/// The service repeats this validation for non-GraphQL callers.
pub(crate) fn normalize_reason(ctx: &Context<'_>, reason: &str) -> Result<String> {
    let reason = reason.trim();
    if reason.chars().count() > 1_000 {
        return Err(app_error(
            ctx,
            rbac::error::InvalidReason::new()
                .min(0)
                .max(1000)
                .with_field("reason"),
        ));
    }
    Ok(reason.to_owned())
}

/// Immutable request authority for every RBAC write. The service never treats it
/// as proof and re-loads the live binding/grant in its transaction.
///
/// The authority carries only verified request facts: the authenticated actor,
/// the delegated management scopes and the optional management snapshot. None
/// of these values come from caller input.
pub(crate) async fn request_authority(
    request: &RequestContext,
) -> StdResult<RbacManagementAuthority, AppError> {
    let token_scopes = request
        .claims
        .scope
        .management_scopes()
        .into_iter()
        .collect::<BTreeSet<ManagementScope>>();
    if request.claims.client_oid.is_nil() {
        return Err(authorization::error::AuthorizationSnapshotExpired.into());
    }
    let (snapshot, boundary) = if request.claims.principal.is_machine() {
        // The transport validated this client credential. Capture its live
        // boundary here; the write transaction compares it under its locks.
        let current = request
            .state
            .services()
            .management_access()
            .client_scope_authority(request.claims.client_oid)
            .await?
            .ok_or_else(|| authorization::error::AuthorizationSnapshotExpired.into_error())?;
        (None, current.boundary)
    } else {
        let management = request
            .claims
            .management
            .as_ref()
            .filter(|data| !data.client_policy_version.is_nil())
            .ok_or_else(|| authorization::error::AuthorizationSnapshotExpired.into_error())?;
        let snapshot = management
            .to_snapshot()
            .map_err(|_| authorization::error::AuthorizationSnapshotExpired.into_error())?;
        (
            Some(snapshot),
            PolicyVersion(management.client_policy_version),
        )
    };
    Ok(RbacManagementAuthority::new(
        request.actor.clone(),
        token_scopes,
        snapshot,
        request.claims.client_oid,
        boundary,
    ))
}
