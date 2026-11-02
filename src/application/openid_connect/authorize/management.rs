//! Approval-time management clipping.
//!
//! Validation may accept a known, client-assigned management request even when
//! the approving user has no binding. The grant itself is decided here, from
//! live authoritative state, and the stored authorization request/code carries
//! only the exact clipped management scope.

use crate::{
    error::{AppError, codes::authorize::AuthorizeErrorCode},
    observability::{BusinessEvent, EventValue},
    openid_connect::management::{
        allowed_human_management_scopes, clipped_scope, human_authentication_is_aal2,
        is_single_graphql_resource,
    },
};
use identity_domain::{
    client_authorization::ManagementAuthorizationSnapshotData,
    openid_connect::{CodeChallengeMethod, ResponseType, ScopeSet},
};
use uuid::Uuid;

use super::AuthorizeService;

pub(super) struct ApprovalAuthentication<'a> {
    pub acr: Option<&'a str>,
    pub amr: &'a [String],
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
        request: &identity_domain::openid_connect::AuthorizationRequestData,
        user_oid: Uuid,
        authentication: ApprovalAuthentication<'_>,
    ) -> Result<identity_domain::openid_connect::AuthorizationRequestData, AppError> {
        let requested_scope = ScopeSet::parse(&request.scope)
            .map_err(AppError::map_source(AuthorizeErrorCode::ScopeInvalid))?;
        if !requested_scope.has_management_scopes() {
            return Ok(request.clone());
        }

        // These invariants are rechecked at approval so a legacy stored request
        // cannot bypass the authorization endpoint validation.
        if request.response_type != ResponseType::Code {
            return Err(AppError::from_code(AuthorizeErrorCode::ResponseTypeInvalid)
                .with_param("response_type", request.response_type.to_string()));
        }
        if requested_scope.contains_offline_access() {
            return Err(
                AppError::from_code(AuthorizeErrorCode::ScopeInvalid).with_param(
                    "scopes",
                    "management and offline_access are mutually exclusive",
                ),
            );
        }
        if !is_single_graphql_resource(&request.resources) {
            return Err(AppError::from_code(
                crate::error::codes::common::CommonErrorCode::InvalidTarget,
            )
            .with_param(
                "resources",
                "management requires the single GraphQL resource",
            ));
        }
        if request.code_challenge.as_deref().is_none_or(str::is_empty)
            || request.code_challenge_method != Some(CodeChallengeMethod::S256)
        {
            return Err(
                AppError::from_code(AuthorizeErrorCode::CodeChallengeMethodInvalid)
                    .with_param("code_challenge_method", "S256 required for management"),
            );
        }

        let client_oid = Uuid::parse_str(&request.client_id).map_err(AppError::map_source(
            AuthorizeErrorCode::StoredClientIdInvalid,
        ))?;
        // Live client lookup: a client deleted after the request was stored
        // cannot receive management authority.
        let client = self
            .client_repo
            .find_by_oid(client_oid)
            .await
            .map_err(AppError::map_source(AuthorizeErrorCode::ClientLookupFailed))?
            .ok_or_else(|| AppError::from_code(AuthorizeErrorCode::ClientNotFound))?;
        self.provider_service
            .validate_client_resource_ceiling(&client, &request.resources, &requested_scope)
            .await
            .map_err(|_| {
                AppError::from_code(AuthorizeErrorCode::ClientGrantNotAllowed)
                    .with_param("reason", "client scope ceiling does not cover the request")
            })?;

        let binding_repo = self.management_authority_repo.as_ref().ok_or_else(|| {
            AppError::from_code(AuthorizeErrorCode::ClientGrantNotAllowed)
                .with_param("reason", "management authority support unavailable")
        })?;
        let authority = binding_repo
            .find_user_permission_authority(identity_domain::user::UserOid(user_oid))
            .await
            .map_err(AppError::map_source(AuthorizeErrorCode::LoadRequestFailed))?;

        let human_aal2 = human_authentication_is_aal2(authentication.acr, authentication.amr);
        let granted =
            allowed_human_management_scopes(&requested_scope, authority.as_ref(), human_aal2);

        let mut clipped_request = request.clone();
        let clipped_scope = clipped_scope(&requested_scope, granted.iter().copied());
        clipped_request.scope = clipped_scope.to_scope_string();

        if granted.is_empty() {
            clipped_request.management = None;
            tracing::Span::current().record(
                "management_requested",
                requested_scope.management_scopes().len() as i64,
            );
            tracing::Span::current().record("management_granted", 0_i64);
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
            return Err(AppError::from_code(
                AuthorizeErrorCode::ClientGrantNotAllowed,
            ));
        };
        let policy_version = binding_repo
            .current_policy_version()
            .await
            .map_err(AppError::map_source(AuthorizeErrorCode::LoadRequestFailed))?;
        let client_fingerprint = self
            .provider_service
            .client_authority_fingerprint(&client)
            .await
            .map_err(AppError::map_source(AuthorizeErrorCode::LoadRequestFailed))?;
        let data = ManagementAuthorizationSnapshotData::for_user_permission_authority(
            &authority,
            policy_version,
            client_fingerprint,
        );
        clipped_request.management = Some(data);

        tracing::Span::current().record(
            "management_requested",
            requested_scope.management_scopes().len() as i64,
        );
        tracing::Span::current().record("management_granted", granted.len() as i64);
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
