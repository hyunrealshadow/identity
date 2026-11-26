//! Approval-time management clipping.
//!
//! Validation may accept a known, client-assigned management request even when
//! the approving user has no binding. The grant itself is decided here, from
//! live authoritative state, and the stored authorization request/code carries
//! only the exact clipped management scope.

use crate::{
    error::{
        AppError,
        codes::{authorize, common},
    },
    observability::{BusinessEvent, EventValue},
    openid_connect::management::{
        allowed_human_management_scopes, clipped_scope, human_authentication_is_multi_factor,
        is_single_graphql_resource,
    },
};
use identity_domain::{
    auth::AuthenticationContextClass,
    client_authorization::ManagementAuthorizationSnapshotData,
    openid_connect::{AuthorizationRequestData, CodeChallengeMethod, ResponseType, ScopeSet},
    user::UserOid,
};
use tracing::Span;
use uuid::Uuid;

use super::AuthorizeService;

pub(super) struct ApprovalAuthentication {
    pub acr: Option<AuthenticationContextClass>,
}

impl AuthorizeService {
    /// Clips management scopes for an approving human. Non-management scopes
    /// are never modified. A request without management keeps its existing
    /// behaviour and does not require management ports.
    #[tracing::instrument(
        skip_all,
        name = "authorization.management.clip",
        fields(
            management_requested = tracing::field::Empty,
            management_granted = tracing::field::Empty
        )
    )]
    pub(super) async fn clip_management_for_approval(
        &self,
        request: &AuthorizationRequestData,
        user_oid: Uuid,
        authentication: ApprovalAuthentication,
    ) -> Result<AuthorizationRequestData, AppError> {
        let requested_scope =
            ScopeSet::parse(&request.scope).map_err(authorize::error::ScopeInvalid::map_source())?;
        if !requested_scope.has_management_scopes() {
            return Ok(request.clone());
        }

        // These invariants are rechecked at approval so a legacy stored request
        // cannot bypass the authorization endpoint validation.
        if request.response_type != ResponseType::Code {
            return Err(
                authorize::error::ResponseTypeInvalid::new(&request.response_type).into_error(),
            );
        }
        if requested_scope.contains_offline_access() {
            return Err(authorize::error::ScopeInvalid.into_error());
        }
        if !is_single_graphql_resource(&request.resources) {
            return Err(common::error::InvalidTarget.into_error());
        }
        if request.code_challenge.as_deref().is_none_or(str::is_empty)
            || request.code_challenge_method != Some(CodeChallengeMethod::S256)
        {
            return Err(authorize::error::CodeChallengeMethodInvalid::new(
                "S256 required for management",
            )
            .into_error());
        }

        let client_oid = Uuid::parse_str(&request.client_id)
            .map_err(authorize::error::StoredClientIdInvalid::map_source())?;
        // Live client lookup: a client deleted after the request was stored
        // cannot receive management authority.
        let client = self
            .client_repo
            .find_by_oid(client_oid)
            .await
            .map_err(authorize::error::ClientLookupFailed::map_source())?
            .ok_or_else(|| authorize::error::ClientNotFound.into_error())?;
        self.provider_service
            .validate_client_resource_ceiling(
                &client,
                &request.resources,
                &requested_scope,
                identity_domain::client_authorization::AccessTokenPrincipal::User,
            )
            .await
            .map_err(|_| authorize::error::ClientGrantNotAllowed.into_error())?;

        let binding_repo = self
            .management_authority_repo
            .as_ref()
            .ok_or_else(|| authorize::error::ClientGrantNotAllowed.into_error())?;
        let authority = binding_repo
            .find_user_permission_authority(UserOid(user_oid))
            .await
            .map_err(authorize::error::LoadRequestFailed::map_source())?;

        let human_aal2 = human_authentication_is_multi_factor(authentication.acr);
        let granted =
            allowed_human_management_scopes(&requested_scope, authority.as_ref(), human_aal2);

        let mut clipped_request = request.clone();
        let clipped_scope = clipped_scope(&requested_scope, granted.iter().copied());
        clipped_request.scope = clipped_scope.to_scope_string();

        if granted.is_empty() {
            clipped_request.management = None;
            Span::current().record(
                "management_requested",
                requested_scope.management_scopes().len() as i64,
            );
            Span::current().record("management_granted", 0_i64);
            self.events.emit(
                BusinessEvent::audit("authorization.management.clipped")
                    .outcome("empty")
                    .attribute("client_oid", EventValue::Text(client_oid.to_string()))
                    .attribute(
                        "management_requested",
                        EventValue::Integer(requested_scope.management_scopes().len() as i64),
                    )
                    .attribute("management_granted", EventValue::Integer(0)),
            );
            return Ok(clipped_request);
        }

        let Some(authority) = authority else {
            // Defensive: allowed scopes cannot be non-empty without authority.
            return Err(authorize::error::ClientGrantNotAllowed.into_error());
        };
        let policy_version = binding_repo
            .current_policy_version()
            .await
            .map_err(authorize::error::LoadRequestFailed::map_source())?;
        let client_fingerprint = self
            .provider_service
            .client_authority_fingerprint(&client)
            .await
            .map_err(authorize::error::LoadRequestFailed::map_source())?;
        let data = ManagementAuthorizationSnapshotData::for_user_permission_authority(
            &authority,
            policy_version,
            client_fingerprint,
        );
        clipped_request.management = Some(data);

        Span::current().record(
            "management_requested",
            requested_scope.management_scopes().len() as i64,
        );
        Span::current().record("management_granted", granted.len() as i64);
        self.events.emit(
            BusinessEvent::audit("authorization.management.clipped")
                .outcome("granted")
                .attribute("client_oid", EventValue::Text(client_oid.to_string()))
                .attribute(
                    "management_requested",
                    EventValue::Integer(requested_scope.management_scopes().len() as i64),
                )
                .attribute(
                    "management_granted",
                    EventValue::Integer(granted.len() as i64),
                )
                .attribute(
                    "management_grant_oid",
                    EventValue::Text(authority.user_oid.0.to_string()),
                ),
        );
        Ok(clipped_request)
    }
}
