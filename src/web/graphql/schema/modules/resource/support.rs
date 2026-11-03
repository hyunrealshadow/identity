//! Shared adapter support for the flat business-RBAC roots.
//!
//! Global IDs, cursor wrapping, page-argument validation and request authority
//! construction are identical for every RBAC functional module. Keeping them in
//! one place prevents one root from silently accepting a different page shape or
//! authority snapshot than its siblings.

use std::{collections::BTreeSet, result::Result as StdResult};

use async_graphql::{Context, ID, Result, connection::CursorType};
use identity_application::{
    error::{
        AppError,
        codes::{
            authorization::AuthorizationErrorCode, graphql::GraphqlErrorCode, rbac::RbacErrorCode,
        },
        params::ErrorParams,
    },
    rbac::RbacManagementAuthority,
};
use identity_domain::authorization::{ManagementScope, PolicyVersion};
use identity_infrastructure::graphql::{
    cursor::InvalidCursor,
    id::{GlobalId, GlobalIdType},
};
use uuid::Uuid;

use crate::graphql::schema::{
    RequestContext,
    error::{app_error, coded_error},
};

const MAX_CURSOR_LENGTH: usize = 512;

/// Opaque, service-minted RBAC cursor.
///
/// The application service binds the token to the normalized filter and order;
/// the adapter only enforces the same syntactic bounds as the P2 user cursor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RbacConnectionCursor(String);

impl RbacConnectionCursor {
    pub(crate) fn from_backend(token: String) -> Self {
        Self(token)
    }
}

impl CursorType for RbacConnectionCursor {
    type Error = InvalidCursor;

    fn decode_cursor(value: &str) -> StdResult<Self, Self::Error> {
        if value.is_empty()
            || value.len() > MAX_CURSOR_LENGTH
            || !value
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
        {
            return Err(InvalidCursor);
        }
        Ok(Self(value.to_owned()))
    }

    fn encode_cursor(&self) -> String {
        self.0.clone()
    }
}

#[derive(Debug, Clone, Default)]
pub(crate) struct PageArgs {
    pub(crate) first: Option<u32>,
    pub(crate) after: Option<String>,
    pub(crate) last: Option<u32>,
    pub(crate) before: Option<String>,
}

/// Reject conflicting page arguments before reaching the application service.
///
/// Native validators already bound `first`/`last` to 1..=100. The service
/// repeats the same checks so a non-GraphQL caller cannot bypass them.
pub(crate) fn page_args(
    ctx: &Context<'_>,
    first: Option<i32>,
    after: Option<String>,
    last: Option<i32>,
    before: Option<String>,
) -> Result<PageArgs> {
    let conflict = first.is_some() && last.is_some()
        || after.is_some() && before.is_some()
        || first.is_some() && before.is_some()
        || last.is_some() && after.is_some();
    if conflict {
        return Err(app_error(
            ctx,
            AppError::from_code(RbacErrorCode::PageArgumentsConflict),
        ));
    }
    Ok(PageArgs {
        first: first.map(|value| value as u32),
        after,
        last: last.map(|value| value as u32),
        before,
    })
}

pub(crate) fn decode_oid<T: GlobalIdType>(ctx: &Context<'_>, id: &ID) -> Result<Uuid> {
    GlobalId::<T>::try_from(id)
        .map(|id| id.oid())
        .map_err(|_| coded_error(ctx, GraphqlErrorCode::InvalidGlobalId, ErrorParams::new()))
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
            AppError::from_code(RbacErrorCode::InvalidReason)
                .with_param("min", "0")
                .with_param("max", "1000")
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
        return Err(AppError::from_code(
            AuthorizationErrorCode::AuthorizationSnapshotExpired,
        ));
    }
    let (snapshot, boundary) = if request.claims.principal.is_machine() {
        use identity_domain::authorization::ManagementAuthorityRepository;
        // The transport validated this client credential. Capture its live
        // boundary here; the write transaction compares it under its locks.
        let current = request
            .state
            .services()
            .authorization()
            .find_client_scope_authority(request.claims.client_oid)
            .await
            .map_err(AppError::from)?
            .ok_or_else(|| {
                AppError::from_code(AuthorizationErrorCode::AuthorizationSnapshotExpired)
            })?;
        (None, current.boundary)
    } else {
        let management = request
            .claims
            .management
            .as_ref()
            .filter(|data| !data.client_policy_version.is_nil())
            .ok_or_else(|| {
                AppError::from_code(AuthorizationErrorCode::AuthorizationSnapshotExpired)
            })?;
        let snapshot = management.to_snapshot().map_err(|_| {
            AppError::from_code(AuthorizationErrorCode::AuthorizationSnapshotExpired)
        })?;
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

#[cfg(test)]
mod tests {
    use async_graphql::connection::CursorType;

    use super::RbacConnectionCursor;

    #[test]
    fn cursor_wrapper_preserves_the_application_token() {
        let token = "Abc-123_xyz".to_owned();
        let cursor = RbacConnectionCursor::from_backend(token.clone());
        assert_eq!(cursor.encode_cursor(), token);
        assert_eq!(
            RbacConnectionCursor::decode_cursor(&token)
                .expect("valid token")
                .encode_cursor(),
            token
        );
    }

    #[test]
    fn cursor_wrapper_rejects_invalid_syntax() {
        assert!(RbacConnectionCursor::decode_cursor("").is_err());
        assert!(RbacConnectionCursor::decode_cursor("not/a/cursor").is_err());
        assert!(RbacConnectionCursor::decode_cursor(&"a".repeat(513)).is_err());
    }
}
