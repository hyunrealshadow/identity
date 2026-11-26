use std::{collections::BTreeSet, sync::Arc};

use async_trait::async_trait;
use chrono::{Duration, Utc};
use identity_domain::{
    authorization::{
        ActorContext, ActorPrincipal, HumanAuthenticationContext, PolicyVersion, RequestId,
    },
    user::{RequiredAction, RequiredActions, UserManagementRecord, UserOid, UserTheme},
};
use uuid::Uuid;

fn change_password() -> RequiredActions {
    [RequiredAction::ChangePassword].into()
}

use super::{
    super::model, UserManagementService, normalize_filter, validate_reason, validate_username_field,
};
use crate::{
    authentication::{
        password::{HashOptions, PasswordHashError, PasswordHasher, VerifyResult},
        password_policy::BreachedPasswordChecker,
    },
    data_protection::DataProtector,
    domain::data_protection::DataProtectionError,
    error::{AppError, kind::ErrorKind},
    setting::{SettingsSnapshot, SettingsSource},
    user::{
        Password,
        management::{
            model::{
                UserFilter, UserManagementAuthority, UserPageRequest, UserProfilePatch,
                UserStateCommand,
            },
            repository::{
                CreateUserTransaction, UpdateUserTransaction, UserManagementMutationOutcome,
                UserManagementPageData, UserManagementQuery, UserManagementRepository,
                UserManagementRepositoryError, UserStateTransaction,
            },
        },
    },
};

struct StubRepository {
    outcome: Option<UserManagementMutationOutcome>,
}

#[async_trait]
impl UserManagementRepository for StubRepository {
    async fn count_users(&self, _filter: UserFilter) -> Result<u64, UserManagementRepositoryError> {
        Ok(0)
    }

    async fn list_users(
        &self,
        _query: UserManagementQuery,
    ) -> Result<UserManagementPageData, UserManagementRepositoryError> {
        Ok(UserManagementPageData {
            items: Vec::new(),
            has_previous_page: false,
            has_next_page: false,
        })
    }

    async fn find_user(
        &self,
        _user_oid: UserOid,
    ) -> Result<Option<UserManagementRecord>, UserManagementRepositoryError> {
        Ok(None)
    }

    async fn find_users(
        &self,
        _user_oids: Vec<UserOid>,
    ) -> Result<Vec<UserManagementRecord>, UserManagementRepositoryError> {
        Ok(Vec::new())
    }

    async fn create_user(
        &self,
        _command: CreateUserTransaction,
    ) -> Result<UserManagementMutationOutcome, UserManagementRepositoryError> {
        Ok(self
            .outcome
            .clone()
            .unwrap_or(UserManagementMutationOutcome::UserNotFound))
    }

    async fn update_user(
        &self,
        _command: UpdateUserTransaction,
    ) -> Result<UserManagementMutationOutcome, UserManagementRepositoryError> {
        Ok(self
            .outcome
            .clone()
            .unwrap_or(UserManagementMutationOutcome::UserNotFound))
    }

    async fn set_user_enabled(
        &self,
        _command: UserStateTransaction,
        _enabled: bool,
    ) -> Result<UserManagementMutationOutcome, UserManagementRepositoryError> {
        Ok(self
            .outcome
            .clone()
            .unwrap_or(UserManagementMutationOutcome::UserNotFound))
    }

    async fn unlock_user(
        &self,
        _command: UserStateTransaction,
    ) -> Result<UserManagementMutationOutcome, UserManagementRepositoryError> {
        Ok(self
            .outcome
            .clone()
            .unwrap_or(UserManagementMutationOutcome::UserNotFound))
    }

    async fn reset_user_password(
        &self,
        _command: UserStateTransaction,
        _password: crate::user::Password,
        _keep_history: u32,
    ) -> Result<UserManagementMutationOutcome, UserManagementRepositoryError> {
        Ok(self
            .outcome
            .clone()
            .unwrap_or(UserManagementMutationOutcome::UserNotFound))
    }

    async fn reset_user_mfa(
        &self,
        _command: UserStateTransaction,
    ) -> Result<UserManagementMutationOutcome, UserManagementRepositoryError> {
        Ok(self
            .outcome
            .clone()
            .unwrap_or(UserManagementMutationOutcome::UserNotFound))
    }

    async fn revoke_user_sessions(
        &self,
        _command: crate::user::management::RevokeUserSessionsTransaction,
    ) -> Result<UserManagementMutationOutcome, UserManagementRepositoryError> {
        Ok(self
            .outcome
            .clone()
            .unwrap_or(UserManagementMutationOutcome::UserNotFound))
    }

    async fn delete_user(
        &self,
        _command: UserStateTransaction,
    ) -> Result<UserManagementMutationOutcome, UserManagementRepositoryError> {
        Ok(self
            .outcome
            .clone()
            .unwrap_or(UserManagementMutationOutcome::UserNotFound))
    }

    async fn send_user_invitation(
        &self,
        _command: crate::user::management::SendUserInvitationTransaction,
    ) -> Result<crate::user::management::UserInvitationOutcome, UserManagementRepositoryError> {
        Ok(crate::user::management::UserInvitationOutcome::UserNotFound)
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

    async fn unprotect(&self, _purpose: &str, token: &str) -> Result<Vec<u8>, DataProtectionError> {
        Ok(token.as_bytes().to_vec())
    }
}

struct TestSettings;

impl SettingsSource for TestSettings {
    fn snapshot(&self) -> Arc<SettingsSnapshot> {
        Arc::new(SettingsSnapshot::default())
    }
}

struct NeverHasher;

impl PasswordHasher for NeverHasher {
    fn hash(&self, _: &str, _: &HashOptions) -> Result<Password, PasswordHashError> {
        Err(PasswordHashError::HashFailed("not used".to_owned()))
    }
    fn verify(
        &self,
        _: &str,
        _: &Password,
        _: &HashOptions,
    ) -> Result<VerifyResult, PasswordHashError> {
        Err(PasswordHashError::HashFailed("not used".to_owned()))
    }
}

struct NeverBreached;

#[async_trait]
impl BreachedPasswordChecker for NeverBreached {
    async fn is_breached(&self, _: &str) -> Result<bool, AppError> {
        Ok(false)
    }
}

fn service(outcome: UserManagementMutationOutcome) -> UserManagementService {
    UserManagementService::new(
        Arc::new(StubRepository {
            outcome: Some(outcome),
        }),
        Arc::new(NeverHasher),
        Arc::new(NeverBreached),
        Arc::new(TestSettings),
        Arc::new(TestProtector),
    )
}

fn authority() -> UserManagementAuthority {
    UserManagementAuthority::new(
        ActorContext::for_user(
            UserOid(Uuid::new_v4()),
            HumanAuthenticationContext::aal2(None),
            RequestId::new("request-1").unwrap(),
            None,
        ),
        BTreeSet::new(),
        None,
        Uuid::new_v4(),
        PolicyVersion::from_uuid(Uuid::new_v4()),
    )
}

fn create_command(password: Option<&str>, send_invitation: bool) -> model::CreateUserCommand {
    model::CreateUserCommand {
        username: "new-user".to_owned(),
        email: "new-user@example.test".to_owned(),
        password: password.map(model::UserPassword::new),
        send_invitation,
        profile: UserProfilePatch::default(),
        reason: String::new(),
        client_mutation_id: None,
    }
}

#[tokio::test]
async fn a_new_user_needs_exactly_one_first_sign_in_method() {
    let service = service(UserManagementMutationOutcome::UserNotFound);
    for command in [
        create_command(None, false),
        create_command(Some("correct horse battery staple"), true),
    ] {
        let error = service
            .create_user(&authority(), command)
            .await
            .unwrap_err();
        assert_eq!(error.code(), 16000);
        assert_eq!(error.children_code(), Some(16029));
    }
}

#[tokio::test]
async fn invitations_need_email_delivery() {
    let service = service(UserManagementMutationOutcome::UserNotFound);
    assert!(!service.invitations_available());
    let error = service
        .create_user(&authority(), create_command(None, true))
        .await
        .unwrap_err();
    assert_eq!(error.code(), 16025);
    let error = service
        .send_user_invitation(
            &authority(),
            model::SendUserInvitationCommand {
                user_oid: UserOid(Uuid::new_v4()),
                reason: String::new(),
                client_mutation_id: None,
            },
        )
        .await
        .unwrap_err();
    assert_eq!(error.code(), 16025);
}

#[test]
fn reason_is_trimmed_and_bounded() {
    assert_eq!(validate_reason("  reviewed  ").unwrap(), "reviewed");
    assert_eq!(validate_reason("   ").unwrap(), "");
    assert_eq!(
        validate_reason(&"x".repeat(1_001))
            .unwrap_err()
            .children_code(),
        Some(16011)
    );
}

#[test]
fn username_validation_preserves_input_and_normalizes_for_uniqueness() {
    assert_eq!(
        validate_username_field(" Alice-01 ").unwrap(),
        ("Alice-01".to_owned(), "alice-01".to_owned())
    );
    assert_eq!(validate_username_field("a").unwrap_err().code(), 16000);
}

#[test]
fn filter_normalization_lowercases_and_rejects_reversed_dates() {
    let filter = UserFilter {
        query: Some("  ADA  ".to_owned()),
        username: Some(" ALICE ".to_owned()),
        ..Default::default()
    };
    let normalized = normalize_filter(filter).unwrap();
    assert_eq!(normalized.query.as_deref(), Some("ada"));
    assert_eq!(normalized.username.as_deref(), Some("alice"));

    let reversed = UserFilter {
        created_from: Some(Utc::now()),
        created_before: Some(Utc::now() - Duration::seconds(1)),
        ..Default::default()
    };
    assert_eq!(normalize_filter(reversed).unwrap_err().code(), 16015);
}

#[tokio::test]
async fn a_stale_version_becomes_a_localized_conflict() {
    let service = service(UserManagementMutationOutcome::VersionConflict {
        current_version: Uuid::new_v4(),
    });
    let error = service
        .unlock_user(
            &authority(),
            UserStateCommand {
                user_oid: UserOid(Uuid::new_v4()),
                expected_version: Uuid::new_v4(),
                reason: "unlock".to_owned(),
                client_mutation_id: None,
            },
        )
        .await
        .unwrap_err();
    assert_eq!(error.code(), 16008);
    assert_eq!(error.kind(), ErrorKind::Conflict);
    assert!(error.params().get("current_version").is_some());
}

#[test]
fn temporary_passwords_are_long_unambiguous_and_distinct() {
    let first = super::temporary_password();
    let second = super::temporary_password();
    assert_ne!(first, second);
    for password in [&first, &second] {
        assert_eq!(password.len(), super::TEMPORARY_PASSWORD_LENGTH);
        assert!(!password.contains('-'));
        assert!(!password.contains(['0', 'O', '1', 'l', 'I']));
        assert!(
            password
                .bytes()
                .all(|b| super::TEMPORARY_PASSWORD_ALL.contains(&b))
        );
        assert!(
            password
                .bytes()
                .any(|b| super::TEMPORARY_PASSWORD_LOWER.contains(&b))
        );
        assert!(
            password
                .bytes()
                .any(|b| super::TEMPORARY_PASSWORD_UPPER.contains(&b))
        );
        assert!(
            password
                .bytes()
                .any(|b| super::TEMPORARY_PASSWORD_DIGITS.contains(&b))
        );
        assert!(
            password
                .bytes()
                .any(|b| super::TEMPORARY_PASSWORD_SYMBOLS.contains(&b))
        );
        crate::authentication::password_policy::validate_password(password, &[], "password")
            .unwrap();
    }
}

#[tokio::test]
async fn refused_admin_operations_become_their_own_errors() {
    let command = || model::UserStateCommand {
        user_oid: UserOid(Uuid::new_v4()),
        expected_version: Uuid::new_v4(),
        reason: String::new(),
        client_mutation_id: None,
    };
    let error = service(UserManagementMutationOutcome::NotDisabled)
        .delete_user(&authority(), command())
        .await
        .unwrap_err();
    assert_eq!(
        error.code(),
        crate::error::codes::user_management::UserManagementErrorCode::UserNotDisabled as u32
    );
    let error = service(UserManagementMutationOutcome::NoPassword)
        .reset_user_mfa(&authority(), command())
        .await
        .unwrap_err();
    assert_eq!(
        error.code(),
        crate::error::codes::user_management::UserManagementErrorCode::UserHasNoPassword as u32
    );
    let error = service(UserManagementMutationOutcome::SessionNotFound)
        .revoke_user_sessions(
            &authority(),
            model::RevokeUserSessionsCommand {
                user_oid: UserOid(Uuid::new_v4()),
                sessions: Some(vec![Uuid::new_v4()]),
                reason: String::new(),
                client_mutation_id: None,
            },
        )
        .await
        .unwrap_err();
    assert_eq!(
        error.code(),
        crate::error::codes::user_management::UserManagementErrorCode::SessionNotFound as u32
    );
}

#[tokio::test]
async fn self_credential_actions_are_refused_for_users_only() {
    let auth = authority();
    let ActorPrincipal::User {
        user_oid: self_oid, ..
    } = auth.actor.principal
    else {
        panic!("expected user actor");
    };
    let service = service(UserManagementMutationOutcome::UserNotFound);
    let state = model::UserStateCommand {
        user_oid: self_oid,
        expected_version: Uuid::new_v4(),
        reason: String::new(),
        client_mutation_id: None,
    };
    let self_code =
        crate::error::codes::user_management::UserManagementErrorCode::SelfCredentialActionNotAllowed as u32;
    let not_found_code =
        crate::error::codes::user_management::UserManagementErrorCode::UserNotFound as u32;

    let err = service
        .reset_user_password(&auth, state.clone())
        .await
        .err()
        .unwrap();
    assert_eq!(err.code(), self_code);

    let err = service.reset_user_mfa(&auth, state).await.unwrap_err();
    assert_eq!(err.code(), self_code);

    let update = |required_actions| model::UpdateUserCommand {
        user_oid: self_oid,
        username: None,
        email: None,
        email_verified: None,
        required_actions,
        profile: UserProfilePatch::default(),
        expected_version: Uuid::new_v4(),
        reason: String::new(),
        client_mutation_id: None,
    };
    let err = service
        .update_user(&auth, update(Some(change_password())))
        .await
        .unwrap_err();
    assert_eq!(err.code(), self_code);

    for keep_or_clear in [None, Some(RequiredActions::new())] {
        let err = service
            .update_user(&auth, update(keep_or_clear))
            .await
            .unwrap_err();
        assert_eq!(err.code(), not_found_code);
    }

    let machine_auth = UserManagementAuthority::new(
        ActorContext::for_client(
            Uuid::new_v4(),
            RequestId::new("request-client").unwrap(),
            None,
        ),
        BTreeSet::new(),
        None,
        Uuid::new_v4(),
        PolicyVersion::from_uuid(Uuid::new_v4()),
    );
    let err = service
        .reset_user_mfa(
            &machine_auth,
            model::UserStateCommand {
                user_oid: self_oid,
                expected_version: Uuid::new_v4(),
                reason: String::new(),
                client_mutation_id: None,
            },
        )
        .await
        .unwrap_err();
    assert_eq!(err.code(), not_found_code);
    let err = service
        .update_user(&machine_auth, update(Some(change_password())))
        .await
        .unwrap_err();
    assert_eq!(err.code(), not_found_code);
}

#[tokio::test]
async fn conflicting_pagination_is_rejected_before_storage() {
    let service = service(UserManagementMutationOutcome::UserNotFound);
    let error = service
        .list_users(UserPageRequest {
            first: Some(10),
            last: Some(5),
            ..Default::default()
        })
        .await
        .unwrap_err();
    assert_eq!(error.code(), 16013);
}

#[test]
fn profile_theme_validation_accepts_supported_values_and_rejects_unknown_values() {
    let parsed = model::parse_theme(Some(Some("dark".to_owned()))).unwrap();
    assert_eq!(parsed.flatten().map(UserTheme::as_str), Some("dark"));
    assert!(model::parse_theme(Some(Some("sepia".to_owned()))).is_err());
    assert!(model::domain_profile_patch(&UserProfilePatch::default()).is_ok());
}

trait ChildCode {
    fn children_code(&self) -> Option<u32>;
}

impl ChildCode for AppError {
    fn children_code(&self) -> Option<u32> {
        self.validation()
            .and_then(|details| details.fields().first())
            .map(|field| field.code())
    }
}
