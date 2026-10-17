use chrono::Utc;
use identity_domain::key::{
    Key, KeyData, KeyOid, KeyType,
    material::{AsymmetricKeyData, SymmetricKeyAlgorithm, SymmetricKeyData},
};
use uuid::Uuid;

use super::{
    TestSigningAlgorithmDetector, generate_ec_p256_pem, generate_ec_p384_pem, generate_ec_p521_pem,
    generate_ec_secp256k1_pem, generate_ed25519_pem, generate_rsa_pem, generate_rsa_pss_pem,
};
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

#[test]
fn empty_keys_returns_empty_vec() {
    let algos = detect_id_token_signing_algorithms(&[], &TestSigningAlgorithmDetector);
    assert!(algos.is_empty());
}

#[test]
fn symmetric_key_is_ignored() {
    let key = make_symmetric_key();
    let algos = detect_id_token_signing_algorithms(&[key], &TestSigningAlgorithmDetector);
    assert!(algos.is_empty());
}

#[test]
fn rsa_key_detects_all_rs_variants() {
    let pem = generate_rsa_pem();
    let key = make_asymmetric_key(pem);
    let algos = detect_id_token_signing_algorithms(&[key], &TestSigningAlgorithmDetector);
    assert!(
        algos.contains(&"RS256".parse().unwrap()),
        "expected RS256, got: {algos:?}"
    );
    assert!(
        algos.contains(&"RS384".parse().unwrap()),
        "expected RS384, got: {algos:?}"
    );
    assert!(
        algos.contains(&"RS512".parse().unwrap()),
        "expected RS512, got: {algos:?}"
    );
}

#[test]
fn rsa_pss_keys_detect_ps_variants() {
    let keys = [
        make_asymmetric_key(generate_rsa_pss_pem("PS256")),
        make_asymmetric_key(generate_rsa_pss_pem("PS384")),
        make_asymmetric_key(generate_rsa_pss_pem("PS512")),
    ];
    let algos = detect_id_token_signing_algorithms(&keys, &TestSigningAlgorithmDetector);
    assert!(
        algos.contains(&"PS256".parse().unwrap()),
        "expected PS256, got: {algos:?}"
    );
    assert!(
        algos.contains(&"PS384".parse().unwrap()),
        "expected PS384, got: {algos:?}"
    );
    assert!(
        algos.contains(&"PS512".parse().unwrap()),
        "expected PS512, got: {algos:?}"
    );
}

#[test]
fn rsa_key_does_not_falsely_detect_ec_algorithms() {
    let pem = generate_rsa_pem();
    let key = make_asymmetric_key(pem);
    let algos = detect_id_token_signing_algorithms(&[key], &TestSigningAlgorithmDetector);
    assert!(!algos.contains(&"ES256".parse().unwrap()));
    assert!(!algos.contains(&"ES256K".parse().unwrap()));
    assert!(!algos.contains(&"EdDSA".parse().unwrap()));
}

#[test]
fn ec_p256_key_detects_es256() {
    let pem = generate_ec_p256_pem();
    let key = make_asymmetric_key(pem);
    let algos = detect_id_token_signing_algorithms(&[key], &TestSigningAlgorithmDetector);
    assert!(
        algos.contains(&"ES256".parse().unwrap()),
        "expected ES256, got: {algos:?}"
    );
}

#[test]
fn ec_p384_key_detects_es384() {
    let key = make_asymmetric_key(generate_ec_p384_pem());
    let algos = detect_id_token_signing_algorithms(&[key], &TestSigningAlgorithmDetector);
    assert_eq!(algos, vec!["ES384".parse().unwrap()]);
}

#[test]
fn ec_p521_key_detects_es512() {
    let key = make_asymmetric_key(generate_ec_p521_pem());
    let algos = detect_id_token_signing_algorithms(&[key], &TestSigningAlgorithmDetector);
    assert_eq!(algos, vec!["ES512".parse().unwrap()]);
}

#[test]
fn ec_secp256k1_key_detects_es256k() {
    let key = make_asymmetric_key(generate_ec_secp256k1_pem());
    let algos = detect_id_token_signing_algorithms(&[key], &TestSigningAlgorithmDetector);
    assert_eq!(algos, vec!["ES256K".parse().unwrap()]);
}

#[test]
fn ed25519_key_detects_eddsa() {
    let key = make_asymmetric_key(generate_ed25519_pem());
    let algos = detect_id_token_signing_algorithms(&[key], &TestSigningAlgorithmDetector);
    assert_eq!(algos, vec!["EdDSA".parse().unwrap()]);
}

#[test]
fn ec_p256_key_does_not_falsely_detect_rs_or_ed_algorithms() {
    let pem = generate_ec_p256_pem();
    let key = make_asymmetric_key(pem);
    let algos = detect_id_token_signing_algorithms(&[key], &TestSigningAlgorithmDetector);
    assert!(!algos.contains(&"RS256".parse().unwrap()));
    assert!(!algos.contains(&"RS384".parse().unwrap()));
    assert!(!algos.contains(&"EdDSA".parse().unwrap()));
}

#[test]
fn mixed_keys_detect_both_families() {
    let rsa_key = make_asymmetric_key(generate_rsa_pem());
    let ps_key = make_asymmetric_key(generate_rsa_pss_pem("PS256"));
    let ec_key = make_asymmetric_key(generate_ec_p256_pem());
    let algos = detect_id_token_signing_algorithms(
        &[rsa_key, ps_key, ec_key],
        &TestSigningAlgorithmDetector,
    );
    assert!(algos.contains(&"RS256".parse().unwrap()));
    assert!(algos.contains(&"RS384".parse().unwrap()));
    assert!(algos.contains(&"RS512".parse().unwrap()));
    assert!(algos.contains(&"PS256".parse().unwrap()));
    assert!(algos.contains(&"ES256".parse().unwrap()));
}
