use std::sync::Arc;

use chrono::Utc;
use sea_orm::DbErr;
use uuid::Uuid;

use super::{OpenIdProviderService, SigningAlgorithmDetector};
use crate::{
    domain::key::{
        JwaSigningAlgorithm, JwkAlgorithm, Key, KeyData, KeyJwk, KeyJwkOid, KeyOid, KeyType,
        PublicJwk, material::AsymmetricKeyData, repository::KeyRepositoryError,
    },
    openid_connect::tests::fixtures::mocks::{MockKeyJwkRepository, MockKeyRepository},
    setting::{
        AppSettings, DynamicRegistrationSettings, InstallationSettings, OpenIdConnectSettings,
        SettingsSnapshot,
    },
};

#[cfg(feature = "oidc-conformance")]
use std::iter;

fn static_settings(
    settings: SettingsSnapshot,
    dynamic_client_registration: bool,
) -> Arc<SettingsSnapshot> {
    Arc::new(settings.with_section(&OpenIdConnectSettings {
        dynamic_registration: DynamicRegistrationSettings {
            enabled: dynamic_client_registration,
        },
        ..OpenIdConnectSettings::default()
    }))
}

#[cfg(feature = "allow-none-alg")]
fn expected_id_token_algorithms(values: &[&str]) -> Vec<String> {
    values
        .iter()
        .copied()
        .chain(iter::once("none"))
        .map(str::to_owned)
        .collect()
}

#[cfg(not(feature = "allow-none-alg"))]
fn expected_id_token_algorithms(values: &[&str]) -> Vec<String> {
    values.iter().copied().map(str::to_owned).collect()
}

fn key_repo_with_keys(keys: Vec<Key>) -> MockKeyRepository {
    let mut mock = MockKeyRepository::new();
    let k = keys.clone();
    mock.expect_find_by_oid()
        .returning(move |oid| Ok(k.iter().find(|key| key.oid == oid).cloned()));
    let k = keys;
    mock.expect_list_active_asymmetric()
        .returning(move || Ok(k.clone()));
    mock.expect_list_decryptable_symmetric()
        .returning(|| Ok(vec![]));
    mock
}

fn key_repo_failing() -> MockKeyRepository {
    let mut mock = MockKeyRepository::new();
    mock.expect_find_by_oid().returning(|_| Ok(None));
    mock.expect_list_active_asymmetric().returning(|| {
        Err(KeyRepositoryError::ListAvailableFailed(Box::new(
            DbErr::Custom("boom".to_owned()),
        )))
    });
    mock.expect_list_decryptable_symmetric()
        .returning(|| Ok(vec![]));
    mock
}

struct TestSigningAlgorithmDetector;

impl SigningAlgorithmDetector for TestSigningAlgorithmDetector {
    fn detect(&self, key: &Key) -> Vec<JwaSigningAlgorithm> {
        let KeyData::Asymmetric(data) = &key.data else {
            return vec![];
        };

        match data.private_key.as_str() {
            "rsa" => vec![
                JwaSigningAlgorithm::Rs256,
                JwaSigningAlgorithm::Rs384,
                JwaSigningAlgorithm::Rs512,
            ],
            "ps256" => vec![JwaSigningAlgorithm::Ps256],
            "ps384" => vec![JwaSigningAlgorithm::Ps384],
            "ps512" => vec![JwaSigningAlgorithm::Ps512],
            "ec-p256" => vec![JwaSigningAlgorithm::Es256],
            "ec-p384" => vec![JwaSigningAlgorithm::Es384],
            "ec-p521" => vec![JwaSigningAlgorithm::Es512],
            "ec-secp256k1" => vec![JwaSigningAlgorithm::Es256k],
            "ed25519" => vec![JwaSigningAlgorithm::EdDsa],
            _ => vec![],
        }
    }
}

fn test_signing_algorithm_detector() -> Arc<dyn SigningAlgorithmDetector> {
    Arc::new(TestSigningAlgorithmDetector)
}

fn make_asymmetric_key(private_key_pem: String) -> Key {
    Key {
        oid: KeyOid(Uuid::new_v4()),
        r#type: KeyType::Asymmetric,
        data: KeyData::Asymmetric(AsymmetricKeyData {
            public_key: String::new(),
            private_key: private_key_pem,
            certificate: None,
        }),
        expires_at: None,
        revoked_at: None,
        created_at: Utc::now(),
        updated_at: None,
    }
}

fn generate_rsa_pem() -> String {
    "rsa".to_owned()
}

fn generate_rsa_pss_pem(alg: &str) -> String {
    match alg {
        "PS256" => "ps256".to_owned(),
        "PS384" => "ps384".to_owned(),
        "PS512" => "ps512".to_owned(),
        other => panic!("unsupported RSA-PSS test alg: {other}"),
    }
}

fn generate_ec_p256_pem() -> String {
    "ec-p256".to_owned()
}

fn generate_ec_p384_pem() -> String {
    "ec-p384".to_owned()
}

fn generate_ec_p521_pem() -> String {
    "ec-p521".to_owned()
}

fn generate_ec_secp256k1_pem() -> String {
    "ec-secp256k1".to_owned()
}

fn generate_ed25519_pem() -> String {
    "ed25519".to_owned()
}

impl OpenIdProviderService {
    pub(super) async fn for_test(state: SettingsSnapshot) -> Self {
        Self::new(static_settings(state, false))
    }

    pub(super) async fn for_test_with_registration(state: SettingsSnapshot) -> Self {
        Self::new(static_settings(state, true))
    }
}

mod algorithms;
mod discovery;
mod scope_catalog;
mod signing;
