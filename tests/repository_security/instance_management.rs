//! Instance settings and key management writes against PostgreSQL: live
//! authority recheck, human-only scopes, optimistic locking, key lifecycle
//! invariants and the semantic audit written with each change.

use chrono::{Duration, Utc};
use identity_application::{
    key::{
        asymmetric::KeyJwkGenerator,
        management::{
            CreateKeyTransaction, KeyManagementRepository, KeyManagementRepositoryError,
            ManagedKeyFilter, ManagedKeyQuery, ManagedKeyStatus, ManagedKeyUse,
            RevokeKeyTransaction, RotateKeyTransaction,
        },
        rotation::KeyRotationMaterialGenerator,
    },
    rbac::{RbacManagementAuthority, cursor::RbacPageDirection},
    setting::{
        SettingChanges,
        management::{
            InstanceSettingRepository, InstanceSettingRepositoryError, InstanceSettingSection,
            UpdateInstanceSettingsTransaction,
        },
    },
};
use identity_domain::{
    authorization::ManagementScope,
    key::{
        AsymmetricKeyAlgorithm, JwaSigningAlgorithm, KeyData, KeyOid, SymmetricKeyAlgorithm,
        SymmetricKeyData,
        generator::{AsymmetricKeyGenerator, AsymmetricKeySpec},
        repository::KeyRepository,
    },
};
use identity_infrastructure::{
    crypto::{
        key::AsymmetricKeyGeneratorImpl, key_jwk::KeyJwkGeneratorImpl,
        key_rotation::KeyRotationMaterialGeneratorImpl,
    },
    database::{
        repository::{
            instance_setting::InstanceSettingRepositoryImpl, key::KeyRepositoryImpl,
            key_management::KeyManagementRepositoryImpl,
        },
        seed,
    },
};
use sea_orm::{ConnectionTrait, DatabaseConnection, DbBackend, Statement};
use uuid::Uuid;

use super::{
    client_management::{administrator, machine, owner},
    common::isolated,
};

async fn audit_count(db: &DatabaseConnection, action: &str, target: Uuid) -> i64 {
    db.query_one_raw(Statement::from_sql_and_values(
        DbBackend::Postgres,
        "SELECT count(*)::bigint AS value FROM security_audit \
         WHERE action=$1 AND target_oid=$2 AND event_kind='semantic'",
        [action.into(), target.into()],
    ))
    .await
    .unwrap()
    .unwrap()
    .try_get("", "value")
    .unwrap()
}

fn enable_registration(
    authority: &RbacManagementAuthority,
    expected_version: Uuid,
) -> UpdateInstanceSettingsTransaction {
    UpdateInstanceSettingsTransaction {
        authority: authority.clone(),
        section: InstanceSettingSection::Protocol,
        expected_version,
        build: Box::new(|state| {
            let mut next = state.openid_connect.clone();
            next.dynamic_registration.enabled = true;
            Ok(SettingChanges::default().set_section(&next)?)
        }),
    }
}

#[tokio::test]
#[ignore = "requires explicitly configured PostgreSQL test database"]
async fn postgres_instance_settings_are_versioned_audited_and_human_only() {
    isolated(|db| async move {
        seed::run_all(&db).await.unwrap();
        owner(&db).await;
        let repo = InstanceSettingRepositoryImpl::new(db.clone());
        let section = InstanceSettingSection::Protocol;
        let before = repo.load().await.unwrap();
        assert!(!before.openid_connect.dynamic_registration.enabled);
        let version = section.version(&before);

        // Settings writes are human-only: a machine principal holding the
        // scope row is rejected and nothing changes.
        let robot = machine(&db, &[ManagementScope::SettingsWrite]).await;
        let denied = repo.update(enable_registration(&robot, version)).await.unwrap_err();
        assert!(matches!(denied, InstanceSettingRepositoryError::Authorization(_)), "{denied:?}");
        assert_eq!(section.version(&repo.load().await.unwrap()), version);

        let owner = administrator(&db, &[ManagementScope::SettingsWrite]).await;
        let after = repo.update(enable_registration(&owner, version)).await.unwrap();
        assert!(after.openid_connect.dynamic_registration.enabled);
        let next = section.version(&after);
        assert_ne!(next, version);
        // Untouched sections keep their version.
        assert_eq!(
            InstanceSettingSection::Authentication.version(&after),
            InstanceSettingSection::Authentication.version(&before)
        );
        assert_eq!(repo.load().await.unwrap(), after);
        assert_eq!(audit_count(&db, "setting.protocol.update", section.audit_target_oid()).await, 1);

        // A stale editor loses: no write and no audit record.
        let stale = repo.update(enable_registration(&owner, version)).await.unwrap_err();
        assert!(matches!(
            stale,
            InstanceSettingRepositoryError::VersionConflict { current_version } if current_version == next
        ));
        assert_eq!(audit_count(&db, "setting.protocol.update", section.audit_target_oid()).await, 1);
    })
    .await;
}

async fn symmetric_key(db: &DatabaseConnection) -> KeyOid {
    KeyRepositoryImpl::new(db.clone())
        .create(
            &KeyData::Symmetric(SymmetricKeyData {
                key: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".to_owned(),
                algorithm: SymmetricKeyAlgorithm::XChaCha20Poly1305,
            }),
            Some(Utc::now() + Duration::days(90)),
        )
        .await
        .unwrap()
        .oid
}

async fn rotate(
    db: &DatabaseConnection,
    authority: &RbacManagementAuthority,
    oid: KeyOid,
) -> Result<identity_application::key::management::KeyRotationResult, KeyManagementRepositoryError>
{
    let repo = KeyManagementRepositoryImpl::new(db.clone());
    let key = repo.find_material(oid).await.unwrap().unwrap();
    let material = KeyRotationMaterialGeneratorImpl.generate(&key).unwrap();
    repo.rotate(RotateKeyTransaction {
        authority: authority.clone(),
        key_oid: oid,
        material,
        revoke_previous: false,
        now: Utc::now(),
    })
    .await
}

fn revoke(authority: &RbacManagementAuthority, oid: KeyOid) -> RevokeKeyTransaction {
    RevokeKeyTransaction {
        authority: authority.clone(),
        key_oid: oid,
        now: Utc::now(),
    }
}

#[tokio::test]
#[ignore = "requires explicitly configured PostgreSQL test database"]
async fn postgres_key_lifecycle_always_keeps_a_key_in_use() {
    isolated(|db| async move {
        seed::run_all(&db).await.unwrap();
        owner(&db).await;
        let repo = KeyManagementRepositoryImpl::new(db.clone());
        let owner = administrator(
            &db,
            &[ManagementScope::KeysRotate, ManagementScope::KeysRevoke],
        )
        .await;
        let original = symmetric_key(&db).await;

        // A key in use cannot be revoked; it must be replaced first.
        let in_use = repo.revoke(revoke(&owner, original)).await.unwrap_err();
        assert!(
            matches!(in_use, KeyManagementRepositoryError::LastActiveKey),
            "{in_use:?}"
        );

        // Rotation is human-only.
        let robot = machine(&db, &[ManagementScope::KeysRotate]).await;
        let denied = rotate(&db, &robot, original).await.unwrap_err();
        assert!(
            matches!(denied, KeyManagementRepositoryError::Authorization(_)),
            "{denied:?}"
        );

        let rotated = rotate(&db, &owner, original).await.unwrap();
        let now = Utc::now();
        assert_eq!(rotated.previous.status(now), ManagedKeyStatus::Retired);
        assert_eq!(rotated.successor.status(now), ManagedKeyStatus::Active);
        assert_eq!(rotated.successor.rotated_from, Some(original));
        assert_eq!(rotated.successor.algorithms, ["XChaCha20-Poly1305"]);
        assert!(rotated.previous.expires_at.unwrap() <= now + Duration::days(30));
        assert_eq!(
            audit_count(&db, "key.rotate", Uuid::from(original)).await,
            1
        );

        // A retired key is not rotated twice.
        let again = rotate(&db, &owner, original).await.unwrap_err();
        assert!(
            matches!(again, KeyManagementRepositoryError::NotActive),
            "{again:?}"
        );

        let active = repo
            .list(ManagedKeyQuery {
                filter: ManagedKeyFilter {
                    key_use: Some(ManagedKeyUse::Encryption),
                    statuses: vec![ManagedKeyStatus::Active],
                },
                now,
                direction: RbacPageDirection::Forward,
                after: None,
                before: None,
                limit: 10,
            })
            .await
            .unwrap();
        assert_eq!(
            active.items.iter().map(|key| key.oid).collect::<Vec<_>>(),
            [rotated.successor.oid]
        );

        let revoked = repo.revoke(revoke(&owner, original)).await.unwrap();
        assert_eq!(revoked.status(Utc::now()), ManagedKeyStatus::Revoked);
        assert_eq!(
            audit_count(&db, "key.revoke", Uuid::from(original)).await,
            1
        );
        let twice = repo.revoke(revoke(&owner, original)).await.unwrap_err();
        assert!(
            matches!(twice, KeyManagementRepositoryError::AlreadyRevoked),
            "{twice:?}"
        );
        assert_eq!(
            audit_count(&db, "key.revoke", Uuid::from(original)).await,
            1
        );

        // Rotate and revoke replaces the key in use and ends it at once.
        let current = rotated.successor.oid;
        let material = KeyRotationMaterialGeneratorImpl
            .generate(&repo.find_material(current).await.unwrap().unwrap())
            .unwrap();
        let replaced = repo
            .rotate(RotateKeyTransaction {
                authority: owner.clone(),
                key_oid: current,
                material,
                revoke_previous: true,
                now: Utc::now(),
            })
            .await
            .unwrap();
        assert_eq!(
            replaced.previous.status(Utc::now()),
            ManagedKeyStatus::Revoked
        );
        assert_eq!(
            replaced.successor.status(Utc::now()),
            ManagedKeyStatus::Active
        );
        assert_eq!(audit_count(&db, "key.rotate", Uuid::from(current)).await, 1);
        assert_eq!(audit_count(&db, "key.revoke", Uuid::from(current)).await, 1);
    })
    .await;
}

#[tokio::test]
#[ignore = "requires explicitly configured PostgreSQL test database"]
async fn postgres_signing_key_rotation_publishes_new_key_ids() {
    isolated(|db| async move {
        seed::run_all(&db).await.unwrap();
        owner(&db).await;
        let owner = administrator(&db, &[ManagementScope::KeysRotate]).await;
        let data = AsymmetricKeyGeneratorImpl
            .generate(&AsymmetricKeySpec {
                algorithm: AsymmetricKeyAlgorithm::EcdsaP256,
                signing: None,
            })
            .unwrap();
        let signing = KeyRepositoryImpl::new(db.clone())
            .create(
                &KeyData::Asymmetric(data),
                Some(Utc::now() + Duration::days(90)),
            )
            .await
            .unwrap()
            .oid;

        let rotated = rotate(&db, &owner, signing).await.unwrap();
        assert_eq!(rotated.successor.key_use, ManagedKeyUse::Signing);
        // The signing algorithm leads; an EC key also publishes ECDH-ES bindings.
        assert_eq!(
            rotated.successor.algorithms.first().map(String::as_str),
            Some("ES256")
        );
        assert!(!rotated.successor.key_ids.is_empty());
        assert!(
            rotated
                .successor
                .key_ids
                .iter()
                .all(|kid| identity_domain::openid_connect::identifier::parse_key_id(kid).is_ok())
        );

        // Another algorithm is added beside it; once it exists, the ES256
        // key in use can be revoked without leaving signing without a key.
        let creator = administrator(
            &db,
            &[ManagementScope::KeysCreate, ManagementScope::KeysRevoke],
        )
        .await;
        let repo = KeyManagementRepositoryImpl::new(db.clone());
        let ed25519 = AsymmetricKeyGeneratorImpl
            .generate(&AsymmetricKeySpec {
                algorithm: AsymmetricKeyAlgorithm::Ed25519,
                signing: None,
            })
            .unwrap();
        let jwks = KeyJwkGeneratorImpl
            .generate(&ed25519.private_key, "pending", None)
            .unwrap();
        let added = repo
            .create(CreateKeyTransaction {
                authority: creator.clone(),
                data: KeyData::Asymmetric(ed25519),
                jwks,
                now: Utc::now(),
            })
            .await
            .unwrap();
        assert_eq!(added.status(Utc::now()), ManagedKeyStatus::Active);
        assert_eq!(added.algorithms.first().map(String::as_str), Some("EdDSA"));
        assert_eq!(
            audit_count(&db, "key.create", Uuid::from(added.oid)).await,
            1
        );

        let revoked = repo
            .revoke(revoke(&creator, rotated.successor.oid))
            .await
            .unwrap();
        assert_eq!(revoked.status(Utc::now()), ManagedKeyStatus::Revoked);
        // A key created for one RSA algorithm keeps that algorithm when it
        // is rotated, although the key could sign with every RS and PS one.
        let rsa = AsymmetricKeyGeneratorImpl
            .generate(&AsymmetricKeySpec::for_signing(
                JwaSigningAlgorithm::Ps256,
                AsymmetricKeyAlgorithm::Rsa2048,
            ))
            .unwrap();
        let jwks = KeyJwkGeneratorImpl
            .generate_for(
                &rsa.private_key,
                "pending",
                None,
                &[JwaSigningAlgorithm::Ps256],
            )
            .unwrap();
        let ps256 = repo
            .create(CreateKeyTransaction {
                authority: creator.clone(),
                data: KeyData::Asymmetric(rsa),
                jwks,
                now: Utc::now(),
            })
            .await
            .unwrap();
        let signing_algorithms =
            |record: &identity_application::key::management::ManagedKeyRecord| {
                record
                    .algorithms
                    .iter()
                    .filter(|algorithm| algorithm.parse::<JwaSigningAlgorithm>().is_ok())
                    .cloned()
                    .collect::<Vec<_>>()
            };
        assert_eq!(signing_algorithms(&ps256), ["PS256"]);
        let rotator = administrator(&db, &[ManagementScope::KeysRotate]).await;
        let rotated_rsa = rotate(&db, &rotator, ps256.oid).await.unwrap();
        assert_eq!(signing_algorithms(&rotated_rsa.successor), ["PS256"]);

        // The RSA successor remains, so the EdDSA key can go; the successor
        // is then the last active signing key and cannot.
        repo.revoke(revoke(&creator, added.oid)).await.unwrap();
        let last = repo
            .revoke(revoke(&creator, rotated_rsa.successor.oid))
            .await
            .unwrap_err();
        assert!(
            matches!(last, KeyManagementRepositoryError::LastActiveKey),
            "{last:?}"
        );
    })
    .await;
}
