use chrono::Utc;
use identity_domain::key::{
    Key, KeyData, KeyOid, KeyType,
    material::{AsymmetricKeyData, SymmetricKeyAlgorithm, SymmetricKeyData},
};
use uuid::Uuid;

use super::{TestSigningAlgorithmDetector, generate_ec_p256_pem, generate_rsa_pem};
use crate::openid_connect::provider::signing::detect_id_token_signing_algorithms;

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

fn make_symmetric_key() -> Key {
    Key {
        oid: KeyOid(Uuid::new_v4()),
        r#type: KeyType::Symmetric,
        data: KeyData::Symmetric(SymmetricKeyData {
            key: "dummy".to_owned(),
            algorithm: SymmetricKeyAlgorithm::XChaCha20Poly1305,
        }),
        expires_at: None,
        revoked_at: None,
        created_at: Utc::now(),
        updated_at: None,
    }
}

// The detector is a test fake; these tests cover only the aggregation rules.
#[test]
fn symmetric_keys_are_ignored_and_shared_algorithms_are_listed_once() {
    let algos = detect_id_token_signing_algorithms(
        &[
            make_symmetric_key(),
            make_asymmetric_key(generate_ec_p256_pem()),
            make_asymmetric_key(generate_rsa_pem()),
            make_asymmetric_key(generate_rsa_pem()),
        ],
        &TestSigningAlgorithmDetector,
    );

    assert_eq!(
        algos,
        vec![
            "ES256".parse().unwrap(),
            "RS256".parse().unwrap(),
            "RS384".parse().unwrap(),
            "RS512".parse().unwrap(),
        ]
    );
}
