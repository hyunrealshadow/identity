use super::*;
use sea_orm::{DatabaseBackend, MockDatabase, MockExecResult, Value};
use std::collections::BTreeMap;

fn id_row(id: i64) -> BTreeMap<String, Value> {
    BTreeMap::from([("id".to_owned(), id.into())])
}

#[tokio::test]
async fn recovery_consumption_uses_the_same_account_lock_as_mfa_mutations() {
    let owner = Uuid::new_v4();
    let db = MockDatabase::new(DatabaseBackend::Postgres)
        .append_query_results([[BTreeMap::from([("oid".to_owned(), Value::from(owner))])]])
        .append_exec_results([
            MockExecResult {
                rows_affected: 0,
                last_insert_id: 0,
            },
            MockExecResult {
                rows_affected: 1,
                last_insert_id: 0,
            },
        ])
        .into_connection();
    assert!(
        consume_recovery_code(&db, UserCredentialOid(Uuid::new_v4()))
            .await
            .unwrap()
    );
    let log = format!("{:?}", db.into_transaction_log());
    assert!(
        log.find("pg_advisory_xact_lock").unwrap() < log.find("DELETE FROM").unwrap(),
        "{log}"
    );
    assert!(
        log.contains("recovery_code") && log.contains("expires_at"),
        "{log}"
    );
}

#[tokio::test]
async fn mfa_removal_is_locked_and_clears_recovery_codes_only_after_the_last_method() {
    for kind in [CredentialType::Otp, CredentialType::Passkey] {
        for remains in [false, true] {
            let db = MockDatabase::new(DatabaseBackend::Postgres)
                .append_query_results([
                    vec![id_row(1)],
                    if remains { vec![id_row(2)] } else { Vec::new() },
                ])
                .append_exec_results([
                    MockExecResult {
                        rows_affected: 0,
                        last_insert_id: 0,
                    },
                    MockExecResult {
                        rows_affected: 1,
                        last_insert_id: 0,
                    },
                    MockExecResult {
                        rows_affected: 10,
                        last_insert_id: 0,
                    },
                ])
                .into_connection();
            let user = UserOid(Uuid::new_v4());
            let repo = UserCredentialRepositoryImpl::new(db.clone());
            let deleted = match kind {
                CredentialType::Otp => UserCredentialRepository::disable_totp(&repo, user)
                    .await
                    .unwrap(),
                _ => PasskeyCredentialRepository::delete(&repo, user, Uuid::new_v4())
                    .await
                    .unwrap(),
            };
            assert!(deleted);
            let log = format!("{:?}", db.into_transaction_log());
            assert!(
                log.find("pg_advisory_xact_lock").unwrap() < log.find("DELETE FROM").unwrap(),
                "{log}"
            );
            assert_eq!(
                log.matches("DELETE FROM").count(),
                if remains { 1 } else { 2 },
                "{log}"
            );
            assert!(
                log.contains("otp") && log.contains("passkey") && log.contains("expires_at"),
                "{log}"
            );
        }
    }
}

#[tokio::test]
async fn adding_mfa_keeps_surviving_codes_without_restoring_consumed_codes() {
    let db = MockDatabase::new(DatabaseBackend::Postgres)
        .append_query_results([[BTreeMap::from([(
            "data".to_owned(),
            Value::from(serde_json::json!({"hash":"surviving"})),
        )])]])
        .into_connection();
    let txn = db.begin().await.unwrap();
    install_recovery_codes(
        &txn,
        1,
        &[
            RecoveryCodeCredentialData {
                hash: "surviving".to_owned(),
            },
            RecoveryCodeCredentialData {
                hash: "already-consumed".to_owned(),
            },
        ],
    )
    .await
    .unwrap();
    txn.commit().await.unwrap();
    let log = format!("{:?}", db.into_transaction_log());
    assert!(
        !log.contains("INSERT INTO") && !log.contains("DELETE FROM"),
        "{log}"
    );
}

#[tokio::test]
async fn missing_or_competing_recovery_enrollment_cannot_enable_a_new_mfa_method() {
    for existing in [None, Some("different-batch")] {
        let rows = existing
            .map(|hash| {
                BTreeMap::from([(
                    "data".to_owned(),
                    Value::from(serde_json::json!({"hash":hash})),
                )])
            })
            .into_iter()
            .collect::<Vec<_>>();
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_results([rows])
            .into_connection();
        let txn = db.begin().await.unwrap();
        let prepared = existing
            .map(|_| RecoveryCodeCredentialData {
                hash: "pending-batch".to_owned(),
            })
            .into_iter()
            .collect::<Vec<_>>();
        assert!(matches!(
            install_recovery_codes(&txn, 1, &prepared)
                .await
                .unwrap_err(),
            UserCredentialRepositoryError::InvalidMfaEnrollment
        ));
        txn.rollback().await.unwrap();
        let log = format!("{:?}", db.into_transaction_log());
        assert!(
            !log.contains("INSERT INTO") && !log.contains("DELETE FROM"),
            "{log}"
        );
    }
}
