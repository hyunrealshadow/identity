use super::*;
use identity_domain::client_authorization::{
    ConsentState, SelectionSource, StoredAuthorizationRequest,
};
use identity_domain::openid_connect::AuthorizationRequest;
use identity_domain::openid_connect::AuthorizationRequestData;

use crate::openid_connect::tests::fixtures::mocks::MockClientAuthorizationRepository;

/// State held by the mockall-based ClientAuthorizationRepository mock.
///
/// Kept public so test helpers can manipulate records directly.
pub(in crate::openid_connect) struct ClientAuthorizationState {
    pub(in crate::openid_connect) records:
        std::sync::Mutex<std::collections::HashMap<uuid::Uuid, ClientAuthorization>>,
}

impl Default for ClientAuthorizationState {
    fn default() -> Self {
        Self {
            records: std::sync::Mutex::new(std::collections::HashMap::new()),
        }
    }
}

// ── State-machine helpers (ported from old InMemoryClientAuthorizationRepository) ──

fn can_overwrite_selection(current: Option<SelectionSource>, next: SelectionSource) -> bool {
    match (current, next) {
        (Some(SelectionSource::FreshLogin), SelectionSource::AccountPicker) => false,
        (Some(existing), incoming) if existing == incoming => true,
        (Some(SelectionSource::Auto), SelectionSource::AccountPicker) => true,
        (Some(SelectionSource::Auto), SelectionSource::FreshLogin) => true,
        (None, _) => true,
        _ => true,
    }
}

// ── Public test helpers (replace the old InMemoryClientAuthorizationRepository methods) ──

/// Insert a legacy authorization request record (plain AuthorizationRequestData, not wrapped).
pub(in crate::openid_connect) fn insert_legacy_authorization_request_for_test(
    state: &ClientAuthorizationState,
    request: &AuthorizationRequest,
) -> uuid::Uuid {
    let oid = uuid::Uuid::new_v4();
    state.records.lock().unwrap().insert(
        oid,
        ClientAuthorization {
            oid,
            client_oid: request.client_id,
            type_: ClientAuthorizationType::AuthorizationRequest,
            data: serde_json::to_value(AuthorizationRequestData::from(request)).unwrap(),
            expires_at: chrono::Utc::now() + chrono::Duration::minutes(10),
            completed_at: None,
            revoked_at: None,
            created_at: chrono::Utc::now(),
            updated_at: None,
        },
    );
    oid
}

/// Modify the stored request's redirect_uri on an existing record.
pub(in crate::openid_connect) fn set_stored_request_redirect_uri_for_test(
    state: &ClientAuthorizationState,
    oid: uuid::Uuid,
    redirect_uri: &str,
) {
    let mut records = state.records.lock().unwrap();
    let record = records.get_mut(&oid).unwrap();
    let mut stored =
        serde_json::from_value::<StoredAuthorizationRequest>(record.data.clone()).unwrap();
    stored.request.redirect_uri = redirect_uri.to_string();
    record.data = serde_json::to_value(stored).unwrap();
    record.updated_at = Some(chrono::Utc::now());
}

/// Check whether a record has a completed_at timestamp.
pub(in crate::openid_connect) fn completed_at_for_test(
    state: &ClientAuthorizationState,
    oid: uuid::Uuid,
) -> Option<chrono::DateTime<chrono::Utc>> {
    state
        .records
        .lock()
        .unwrap()
        .get(&oid)
        .and_then(|record| record.completed_at)
}

// ── Mock factory with full state machine ──

/// Creates a MockClientAuthorizationRepository backed by a `ClientAuthorizationState`,
/// implementing the full authorization request state machine.
pub fn mock_client_auth_repo_with_state(
    state: std::sync::Arc<ClientAuthorizationState>,
) -> MockClientAuthorizationRepository {
    let mut mock = MockClientAuthorizationRepository::new();

    // create
    let s = state.clone();
    mock.expect_create()
        .returning(move |client_oid, type_, data, expires_at| {
            let record = ClientAuthorization {
                oid: uuid::Uuid::new_v4(),
                client_oid,
                type_,
                data,
                expires_at,
                completed_at: None,
                revoked_at: None,
                created_at: chrono::Utc::now(),
                updated_at: None,
            };
            s.records.lock().unwrap().insert(record.oid, record.clone());
            Ok(record)
        });

    // find_by_oid
    let s = state.clone();
    mock.expect_find_by_oid()
        .returning(move |oid| Ok(s.records.lock().unwrap().get(&oid).cloned()));

    // update_authorization_request_selection (full state machine)
    let s = state.clone();
    mock.expect_update_authorization_request_selection()
        .returning(
            move |oid, session_oid, user_oid, protected_session_id, source| {
                let mut records = s.records.lock().unwrap();
                let Some(record) = records.get_mut(&oid) else {
                    return Ok(false);
                };
                if record.completed_at.is_some() {
                    return Ok(false);
                }

                let Ok(mut stored) =
                    serde_json::from_value::<StoredAuthorizationRequest>(record.data.clone())
                else {
                    return Ok(false);
                };
                if !can_overwrite_selection(stored.interaction.selection_source, source) {
                    return Ok(false);
                }

                stored.interaction.selected_session_oid = Some(session_oid);
                stored.interaction.selected_protected_session_id = protected_session_id;
                stored.interaction.selected_user_oid = Some(user_oid.to_string());
                stored.interaction.selection_source = Some(source);
                record.data = serde_json::to_value(stored).unwrap();
                record.updated_at = Some(chrono::Utc::now());
                Ok(true)
            },
        );

    // record_authorization_request_consent (full state machine)
    let s = state.clone();
    mock.expect_record_authorization_request_consent()
        .returning(move |oid, consent_state, decided_at| {
            let mut records = s.records.lock().unwrap();
            let Some(record) = records.get_mut(&oid) else {
                return Ok(false);
            };
            if record.completed_at.is_some() {
                return Ok(false);
            }

            let Ok(mut stored) =
                serde_json::from_value::<StoredAuthorizationRequest>(record.data.clone())
            else {
                return Ok(false);
            };
            if stored.interaction.consent_state != ConsentState::Pending {
                return Ok(false);
            }

            stored.interaction.consent_state = consent_state;
            stored.interaction.consent_decided_at = Some(decided_at.to_rfc3339());
            record.data = serde_json::to_value(stored).unwrap();
            record.updated_at = Some(chrono::Utc::now());
            Ok(true)
        });

    // mark_authorization_request_completed
    let s = state.clone();
    mock.expect_mark_authorization_request_completed()
        .returning(move |oid, completed_at| {
            let mut records = s.records.lock().unwrap();
            let Some(record) = records.get_mut(&oid) else {
                return Ok(false);
            };
            if record.completed_at.is_some() {
                return Ok(false);
            }
            record.completed_at = Some(completed_at);
            record.updated_at = Some(chrono::Utc::now());
            Ok(true)
        });

    // revoke_access_tokens_for_authorization_code
    mock.expect_revoke_access_tokens_for_authorization_code()
        .returning(move |_authorization_code_oid| Ok(()));

    // revoke_if_active
    let s = state.clone();
    mock.expect_revoke_if_active()
        .returning(move |oid, type_, now| {
            let mut records = s.records.lock().unwrap();
            let Some(record) = records.get_mut(&oid) else {
                return Ok(false);
            };
            if record.type_ != type_ || record.revoked_at.is_some() || record.expires_at <= now {
                return Ok(false);
            }

            record.revoked_at = Some(now);
            record.updated_at = Some(now);
            Ok(true)
        });

    // revoke
    let s = state;
    mock.expect_revoke().returning(move |oid| {
        if let Some(record) = s.records.lock().unwrap().get_mut(&oid) {
            record.revoked_at = Some(chrono::Utc::now());
        }
        Ok(())
    });

    mock
}
