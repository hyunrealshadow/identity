//! Instance administrator management use cases.
//!
//! Entry Guards establish that the caller held `management.administrator.read`
//! or `.write` when the request started. Every write passes immutable request
//! authority to the repository, which re-loads the live actor binding, exact
//! snapshot, issuing client policy, target owner state and target version
//! inside one write transaction.

use std::sync::Arc;

use identity_domain::authorization::{
    AdministratorBinding, AdministratorBindingOid, GrantReason, GrantReasonError,
    OwnerProtectionError,
};
use uuid::Uuid;

use crate::{
    data_protection::DataProtector,
    error::{
        AppError,
        codes::{administrator::AdministratorErrorCode, authorization::AuthorizationErrorCode},
    },
    observability::{BusinessEvent, EventSink, EventValue, NoopEventSink, error_outcome},
};

use super::{
    cursor::{NormalizedFilter, encode_cursor, prepare_page},
    model::{
        AdministratorFilter, AdministratorManagementAuthority, AdministratorPage,
        AdministratorPageItem, AdministratorPageRequest, AssignAdministratorCommand,
        MAX_QUERY_FILTER_LENGTH, MAX_REASON_LENGTH, RevokeAdministratorCommand,
        UpdateAdministratorRoleCommand,
    },
    repository::{
        AdministratorManagementRepository, AdministratorManagementRepositoryError,
        AdministratorQuery, AssignAdministratorTransaction, RevokeAdministratorTransaction,
        UpdateAdministratorRoleTransaction,
    },
};

pub struct AdministratorManagementService {
    repository: Arc<dyn AdministratorManagementRepository>,
    data_protector: Arc<dyn DataProtector>,
    events: Arc<dyn EventSink>,
}

impl AdministratorManagementService {
    #[must_use]
    pub fn new(
        repository: Arc<dyn AdministratorManagementRepository>,
        data_protector: Arc<dyn DataProtector>,
    ) -> Self {
        Self {
            repository,
            data_protector,
            events: Arc::new(NoopEventSink),
        }
    }

    #[must_use]
    pub fn with_events(mut self, events: Arc<dyn EventSink>) -> Self {
        self.events = events;
        self
    }

    #[tracing::instrument(skip_all, name = "administrator.management.find")]
    pub async fn find_administrator(
        &self,
        oid: AdministratorBindingOid,
    ) -> Result<Option<AdministratorBinding>, AppError> {
        self.repository
            .find_administrator(oid)
            .await
            .map_err(map_repository_error)
    }

    #[tracing::instrument(skip_all, name = "administrator.management.list")]
    pub async fn list_administrators(
        &self,
        request: AdministratorPageRequest,
    ) -> Result<AdministratorPage, AppError> {
        let filter = normalize_filter(request.filter)?;
        let order = request.order;
        let prepared = prepare_page(
            self.data_protector.as_ref(),
            &filter,
            order,
            request.first,
            request.after,
            request.last,
            request.before,
        )
        .await?;
        let data = self
            .repository
            .list_administrators(AdministratorQuery {
                filter: AdministratorFilter::from(&filter),
                order,
                direction: prepared.direction,
                after: prepared.after,
                before: prepared.before,
                limit: prepared.limit,
            })
            .await
            .map_err(map_repository_error)?;
        let mut items = Vec::with_capacity(data.items.len());
        for entry in data.items {
            let cursor = encode_cursor(
                self.data_protector.as_ref(),
                &filter,
                order,
                &entry.sort_key,
            )
            .await?;
            items.push(AdministratorPageItem {
                binding: entry.binding,
                cursor,
            });
        }
        Ok(AdministratorPage {
            items,
            has_previous_page: data.has_previous_page,
            has_next_page: data.has_next_page,
        })
    }

    #[tracing::instrument(skip_all, name = "administrator.management.assign")]
    pub async fn assign_administrator(
        &self,
        authority: &AdministratorManagementAuthority,
        command: AssignAdministratorCommand,
    ) -> Result<AdministratorBinding, AppError> {
        let result = async {
            let reason = validate_reason(&command.reason)?;
            self.repository
                .assign_administrator(AssignAdministratorTransaction {
                    user_oid: command.user_oid,
                    role: command.role,
                    reason,
                    authority: authority.clone(),
                })
                .await
                .map_err(map_repository_error)
        }
        .await;
        self.emit_mutation("administrator.management.assign", &result);
        result
    }

    #[tracing::instrument(skip_all, name = "administrator.management.role.update")]
    pub async fn update_administrator_role(
        &self,
        authority: &AdministratorManagementAuthority,
        command: UpdateAdministratorRoleCommand,
    ) -> Result<AdministratorBinding, AppError> {
        let result = async {
            let reason = validate_reason(&command.reason)?;
            self.repository
                .update_administrator_role(UpdateAdministratorRoleTransaction {
                    binding_oid: command.binding_oid,
                    role: command.role,
                    expected_version: command.expected_version,
                    reason,
                    authority: authority.clone(),
                })
                .await
                .map_err(map_repository_error)
        }
        .await;
        self.emit_mutation("administrator.management.role.update", &result);
        result
    }

    #[tracing::instrument(skip_all, name = "administrator.management.revoke")]
    pub async fn revoke_administrator(
        &self,
        authority: &AdministratorManagementAuthority,
        command: RevokeAdministratorCommand,
    ) -> Result<AdministratorBinding, AppError> {
        let result = async {
            let reason = validate_reason(&command.reason)?;
            self.repository
                .revoke_administrator(RevokeAdministratorTransaction {
                    binding_oid: command.binding_oid,
                    expected_version: command.expected_version,
                    reason,
                    authority: authority.clone(),
                })
                .await
                .map_err(map_repository_error)
        }
        .await;
        self.emit_mutation("administrator.management.revoke", &result);
        result
    }

    fn emit_mutation(&self, name: &'static str, result: &Result<AdministratorBinding, AppError>) {
        let mut event = BusinessEvent::business(name);
        match result {
            Ok(binding) => {
                event = event.outcome("success").attribute(
                    "administrator_binding_oid",
                    EventValue::Pseudonymized {
                        purpose: "administrator_binding_oid",
                        value: Uuid::from(binding.oid).to_string(),
                    },
                );
            }
            Err(error) => {
                let (outcome, reason) = error_outcome(error);
                event = event
                    .outcome(outcome)
                    .reason(reason)
                    .attribute("error_code", EventValue::Integer(i64::from(error.code())));
            }
        }
        self.events.emit(event);
    }
}

/// Normalize an optional audit annotation shared by every administrator
/// mutation. Blank input becomes an empty reason; only over-long supplied text
/// is rejected.
fn validate_reason(reason: &str) -> Result<GrantReason, AppError> {
    let reason = reason.trim();
    if reason.chars().count() > MAX_REASON_LENGTH {
        return Err(AppError::from_code(AdministratorErrorCode::ReasonTooLong)
            .with_param("max", MAX_REASON_LENGTH.to_string())
            .with_field("reason"));
    }
    GrantReason::new(reason).map_err(|error| match error {
        GrantReasonError::TooLong => AppError::from_code(AdministratorErrorCode::ReasonTooLong)
            .with_param("max", MAX_REASON_LENGTH.to_string())
            .with_field("reason"),
    })
}

fn normalize_filter(filter: AdministratorFilter) -> Result<NormalizedFilter, AppError> {
    let query = match filter.query {
        Some(value) => {
            let value = value.trim();
            if value.is_empty() {
                None
            } else if value.chars().count() > MAX_QUERY_FILTER_LENGTH {
                return Err(AppError::from_code(AdministratorErrorCode::InvalidFilter)
                    .with_param("field", "query")
                    .with_param("max", MAX_QUERY_FILTER_LENGTH.to_string())
                    .with_field("query"));
            } else {
                Some(value.to_lowercase())
            }
        }
        None => None,
    };
    Ok(NormalizedFilter {
        query,
        role: filter.role,
        enabled: filter.enabled,
        user_oid: filter.user_oid,
    })
}

fn map_repository_error(error: AdministratorManagementRepositoryError) -> AppError {
    match error {
        source @ AdministratorManagementRepositoryError::Storage(_) => {
            AppError::from_code(AdministratorErrorCode::StorageFailed).with_source(source)
        }
        AdministratorManagementRepositoryError::Authorization(source) => AppError::from(source),
        source @ AdministratorManagementRepositoryError::AuditFailed(_) => {
            AppError::from_code(AuthorizationErrorCode::AuditWriteFailed).with_source(source)
        }
        source @ AdministratorManagementRepositoryError::CorruptRecord => {
            AppError::from_code(AdministratorErrorCode::StorageFailed).with_source(source)
        }
        AdministratorManagementRepositoryError::UserNotFound => {
            AppError::from_code(AdministratorErrorCode::UserNotFound).with_field("userId")
        }
        AdministratorManagementRepositoryError::AdministratorNotFound => {
            AppError::from_code(AuthorizationErrorCode::BindingNotFound).with_field("id")
        }
        AdministratorManagementRepositoryError::AlreadyAssigned => {
            AppError::from_code(AdministratorErrorCode::AlreadyAssigned).with_field("userId")
        }
        AdministratorManagementRepositoryError::AlreadyRevoked => {
            AppError::from_code(AuthorizationErrorCode::BindingAlreadyRevoked)
        }
        AdministratorManagementRepositoryError::VersionConflict { current_version } => {
            AppError::from_code(AuthorizationErrorCode::VersionConflict)
                .with_param("current_version", current_version.to_string())
                .with_field("expectedVersion")
        }
        AdministratorManagementRepositoryError::LastOwnerProtected => {
            AppError::from(OwnerProtectionError::LastOwnerProtected)
        }
        AdministratorManagementRepositoryError::AccountInactive => {
            AppError::from_code(AdministratorErrorCode::AccountInactive)
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use async_trait::async_trait;
    use identity_domain::{
        authorization::{
            ActorContext, AdministratorBinding, AdministratorBindingOid, AuthorizationVersion,
            PolicyVersion,
        },
        user::UserOid,
    };

    use super::{
        AdministratorManagementService, map_repository_error, normalize_filter, validate_reason,
    };
    use crate::{
        administrator::{
            model::{
                AdministratorFilter, AdministratorManagementAuthority, AdministratorPageRequest,
            },
            repository::{
                AdministratorManagementRepository, AdministratorManagementRepositoryError,
                AdministratorPageData, AdministratorQuery, AssignAdministratorTransaction,
                RevokeAdministratorTransaction, UpdateAdministratorRoleTransaction,
            },
        },
        data_protection::DataProtector,
        domain::data_protection::DataProtectionError,
        error::kind::ErrorKind,
    };

    struct StubRepository;

    #[async_trait]
    impl AdministratorManagementRepository for StubRepository {
        async fn find_administrator(
            &self,
            _oid: AdministratorBindingOid,
        ) -> Result<Option<AdministratorBinding>, AdministratorManagementRepositoryError> {
            Ok(None)
        }

        async fn list_administrators(
            &self,
            _query: AdministratorQuery,
        ) -> Result<AdministratorPageData, AdministratorManagementRepositoryError> {
            Ok(AdministratorPageData {
                items: Vec::new(),
                has_previous_page: false,
                has_next_page: false,
            })
        }

        async fn assign_administrator(
            &self,
            _command: AssignAdministratorTransaction,
        ) -> Result<AdministratorBinding, AdministratorManagementRepositoryError> {
            Err(AdministratorManagementRepositoryError::UserNotFound)
        }

        async fn update_administrator_role(
            &self,
            _command: UpdateAdministratorRoleTransaction,
        ) -> Result<AdministratorBinding, AdministratorManagementRepositoryError> {
            Err(AdministratorManagementRepositoryError::AdministratorNotFound)
        }

        async fn revoke_administrator(
            &self,
            _command: RevokeAdministratorTransaction,
        ) -> Result<AdministratorBinding, AdministratorManagementRepositoryError> {
            Err(AdministratorManagementRepositoryError::AlreadyRevoked)
        }
    }

    struct TestProtector;

    #[async_trait]
    impl DataProtector for TestProtector {
        async fn protect(
            &self,
            _purpose: &str,
            plaintext: &[u8],
        ) -> Result<String, DataProtectionError> {
            Ok(String::from_utf8_lossy(plaintext).into_owned())
        }

        async fn unprotect(
            &self,
            _purpose: &str,
            token: &str,
        ) -> Result<Vec<u8>, DataProtectionError> {
            Ok(token.as_bytes().to_vec())
        }
    }

    fn service() -> AdministratorManagementService {
        AdministratorManagementService::new(Arc::new(StubRepository), Arc::new(TestProtector))
    }

    fn authority() -> AdministratorManagementAuthority {
        AdministratorManagementAuthority::new(
            ActorContext::for_user(
                UserOid(uuid::Uuid::new_v4()),
                identity_domain::authorization::HumanAuthenticationContext::aal2(None),
                identity_domain::authorization::RequestId::new("request-1").unwrap(),
                None,
            ),
            std::collections::BTreeSet::new(),
            None,
            uuid::Uuid::new_v4(),
            PolicyVersion::new(),
        )
    }

    #[test]
    fn reason_is_trimmed_and_bounded() {
        assert_eq!(
            validate_reason("  reviewed  ").unwrap().as_str(),
            "reviewed"
        );
        assert_eq!(validate_reason("   ").unwrap().as_str(), "");
        assert_eq!(
            validate_reason(&"x".repeat(1_001)).unwrap_err().code(),
            18003
        );
    }

    #[test]
    fn filter_normalization_lowercases_and_bounds_query() {
        let normalized = normalize_filter(AdministratorFilter {
            query: Some("  ADA  ".to_owned()),
            ..Default::default()
        })
        .unwrap();
        assert_eq!(normalized.query.as_deref(), Some("ada"));
        let error = normalize_filter(AdministratorFilter {
            query: Some("x".repeat(256)),
            ..Default::default()
        })
        .unwrap_err();
        assert_eq!(error.code(), 18006);
        assert_eq!(error.params().get("max"), Some("255"));
    }

    #[tokio::test]
    async fn conflicting_pagination_is_rejected_before_storage() {
        let error = service()
            .list_administrators(AdministratorPageRequest {
                first: Some(10),
                last: Some(5),
                ..Default::default()
            })
            .await
            .unwrap_err();
        assert_eq!(error.code(), 18005);
    }

    #[tokio::test]
    async fn repository_outcomes_map_to_localized_codes() {
        let error = service()
            .revoke_administrator(
                &authority(),
                crate::administrator::model::RevokeAdministratorCommand {
                    binding_oid: AdministratorBindingOid::new(),
                    expected_version: AuthorizationVersion::new(),
                    reason: "revoke".to_owned(),
                },
            )
            .await
            .unwrap_err();
        assert_eq!(error.code(), 27010);
        assert_eq!(error.kind(), ErrorKind::Conflict);
        let current_version = AuthorizationVersion::new();
        let mapped =
            map_repository_error(AdministratorManagementRepositoryError::VersionConflict {
                current_version,
            });
        let current_version_text = current_version.to_string();
        assert_eq!(
            mapped.params().get("current_version"),
            Some(current_version_text.as_str())
        );
        let missing = map_repository_error(AdministratorManagementRepositoryError::UserNotFound);
        assert_eq!(missing.code(), 18010);
        assert_eq!(missing.kind(), ErrorKind::NotFound);
    }
}
