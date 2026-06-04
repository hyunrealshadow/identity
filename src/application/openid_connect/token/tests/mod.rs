use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};

use async_trait::async_trait;
use base64::{
    Engine as _,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use chrono::Utc;
use josekit::jwk::KeyPair;
use josekit::{
    jws::{
        ES256, ES256K, ES384, ES512, EdDSA, HS256, HS384, HS512, JwsHeader, PS256, PS384, PS512,
        RS256, RS384, RS512,
    },
    jwt,
    jwt::JwtPayload,
};
use openssl::rsa::Rsa;
use sha2::{Digest, Sha256, Sha384, Sha512};
use uuid::Uuid;

use super::{AuthorizationCodeGrantParams, RefreshTokenGrantParams, TokenService, verify_pkce};
use crate::{
    application::{
        error::AppError,
        key::asymmetric::{AsymmetricKeyService, GeneratedKeyJwk, KeyJwkGenerator},
        openid_connect::provider::{OpenIdProviderService, SigningAlgorithmDetector},
        setting::runtime::SettingProvider,
    },
    domain::{
        client::model::ClientOid,
        client_authorization::{
            AccessTokenData, AuthorizationCodeData, ClientAuthorization,
            ClientAuthorizationRepository, ClientAuthorizationRepositoryError,
            ClientAuthorizationType, RefreshTokenData,
        },
        key::generator::{AsymmetricKeyGenerator, AsymmetricKeySpec, KeyMaterialError},
        key::{
            JwaSigningAlgorithm, Key, KeyData, KeyOid, KeyType, PublicJwk,
            material::AsymmetricKeyData,
        },
        key::{KeyJwk, KeyJwkOid},
        openid_connect::{
            OpenIdConnectClient, OpenIdConnectClientRepository, OpenIdConnectClientRepositoryError,
            OpenIdConnectCredential, OpenIdConnectCredentialData, OpenIdConnectCredentialType,
            model::claim::JwtClaimNames,
        },
        setting::installation::{InstallationSetting, InstallationState},
        user::{
            User, UserOid,
            repository::{UserRepository, UserRepositoryError},
        },
    },
};

mod auth;
mod exchange;
mod fixtures;
mod helpers;

use self::fixtures::{
    InMemoryClientRepository, InMemoryDataProtector, InMemoryUserRepository,
    MockClientAuthorizationRepository, cred_repo_with, jwk_repo_with_bindings, key_repo_with_keys,
    mock_client_auth_repo, provider_service, signing_algorithm_detector,
};

fn expected_at_hash(access_token: &str) -> String {
    expected_at_hash_for_alg(access_token, "RS256")
}

fn expected_at_hash_for_alg(access_token: &str, alg: &str) -> String {
    match alg {
        "RS384" | "PS384" | "ES384" => {
            let digest = Sha384::digest(access_token.as_bytes());
            URL_SAFE_NO_PAD.encode(&digest[..24])
        }
        "RS512" | "PS512" | "ES512" | "EdDSA" => {
            let digest = Sha512::digest(access_token.as_bytes());
            URL_SAFE_NO_PAD.encode(&digest[..32])
        }
        _ => {
            let digest = Sha256::digest(access_token.as_bytes());
            URL_SAFE_NO_PAD.encode(&digest[..16])
        }
    }
}

fn key_jwk_binding(key: &Key, alg: &str, binding_oid: Uuid) -> KeyJwk {
    let private_key = match &key.data {
        KeyData::Asymmetric(data) => data.private_key.as_str(),
        KeyData::Symmetric(_) => panic!("signing key bindings require asymmetric keys"),
    };

    let mut jwk = if let Ok(key_pair) =
        josekit::jwk::alg::rsapss::RsaPssKeyPair::from_pem(private_key, None, None, None)
    {
        key_pair.to_jwk_public_key()
    } else if let Ok(key_pair) = josekit::jwk::alg::rsa::RsaKeyPair::from_pem(private_key) {
        key_pair.to_jwk_public_key()
    } else if let Ok(key_pair) = josekit::jwk::alg::ec::EcKeyPair::from_pem(private_key, None) {
        key_pair.to_jwk_public_key()
    } else if let Ok(key_pair) = josekit::jwk::alg::ed::EdKeyPair::from_pem(private_key) {
        key_pair.to_jwk_public_key()
    } else {
        panic!("unsupported test key format");
    };

    jwk.set_key_use("sig");
    jwk.set_algorithm(alg);
    jwk.set_key_id(binding_oid.to_string());

    KeyJwk {
        oid: KeyJwkOid::from(binding_oid),
        key_oid: key.oid,
        algorithm: alg.to_owned(),
        jwk: serde_json::from_value::<PublicJwk>(serde_json::to_value(jwk).unwrap()).unwrap(),
        created_at: Utc::now(),
    }
}

fn key_for_algorithm(alg: &str) -> Key {
    if let Some(data) = rsa_pss_key_for_algorithm(alg) {
        return Key {
            oid: KeyOid(Uuid::new_v4()),
            r#type: KeyType::Asymmetric,
            data: KeyData::Asymmetric(AsymmetricKeyData {
                certificate: Some(alg.to_owned()),
                ..data
            }),
            expires_at: None,
            revoked_at: None,
            created_at: Utc::now(),
            updated_at: None,
        };
    }

    let data = key_data_for_algorithm(alg);
    Key {
        oid: KeyOid(Uuid::new_v4()),
        r#type: KeyType::Asymmetric,
        data: KeyData::Asymmetric(AsymmetricKeyData {
            certificate: Some(alg.to_owned()),
            ..data
        }),
        expires_at: None,
        revoked_at: None,
        created_at: Utc::now(),
        updated_at: None,
    }
}

fn key_data_for_algorithm(alg: &str) -> AsymmetricKeyData {
    match alg {
        "RS256" => rsa_key_data(2048),
        "RS384" => rsa_key_data(3072),
        "RS512" => rsa_key_data(4096),
        "ES256" => ec_key_data(josekit::jwk::alg::ec::EcCurve::P256),
        "ES384" => ec_key_data(josekit::jwk::alg::ec::EcCurve::P384),
        "ES512" => ec_key_data(josekit::jwk::alg::ec::EcCurve::P521),
        "ES256K" => ec_key_data(josekit::jwk::alg::ec::EcCurve::Secp256k1),
        "EdDSA" => ed_key_data(josekit::jwk::alg::ed::EdCurve::Ed25519),
        other => panic!("unsupported test alg: {other}"),
    }
}

fn rsa_key_data(bits: u32) -> AsymmetricKeyData {
    let jwk = josekit::jwk::Jwk::generate_rsa_key(bits).unwrap();
    let key_pair = josekit::jwk::alg::rsa::RsaKeyPair::from_jwk(&jwk).unwrap();
    AsymmetricKeyData {
        private_key: String::from_utf8(key_pair.to_pem_private_key()).unwrap(),
        public_key: String::from_utf8(key_pair.to_pem_public_key()).unwrap(),
        certificate: None,
    }
}

fn ec_key_data(curve: josekit::jwk::alg::ec::EcCurve) -> AsymmetricKeyData {
    let jwk = josekit::jwk::Jwk::generate_ec_key(curve).unwrap();
    let key_pair = josekit::jwk::alg::ec::EcKeyPair::from_jwk(&jwk).unwrap();
    AsymmetricKeyData {
        private_key: String::from_utf8(key_pair.to_pem_private_key()).unwrap(),
        public_key: String::from_utf8(key_pair.to_pem_public_key()).unwrap(),
        certificate: None,
    }
}

fn ed_key_data(curve: josekit::jwk::alg::ed::EdCurve) -> AsymmetricKeyData {
    let jwk = josekit::jwk::Jwk::generate_ed_key(curve).unwrap();
    let key_pair = josekit::jwk::alg::ed::EdKeyPair::from_jwk(&jwk).unwrap();
    AsymmetricKeyData {
        private_key: String::from_utf8(key_pair.to_pem_private_key()).unwrap(),
        public_key: String::from_utf8(key_pair.to_pem_public_key()).unwrap(),
        certificate: None,
    }
}

struct TestKeyJwkGenerator;

struct TestAsymmetricKeyGenerator;

impl AsymmetricKeyGenerator for TestAsymmetricKeyGenerator {
    fn generate(&self, _spec: &AsymmetricKeySpec) -> Result<AsymmetricKeyData, KeyMaterialError> {
        Ok(key_data_for_algorithm("RS256"))
    }
}

impl KeyJwkGenerator for TestKeyJwkGenerator {
    fn generate(
        &self,
        _private_key_pem: &str,
        _key_id: &str,
        _certificate_pem: Option<&str>,
    ) -> Result<Vec<GeneratedKeyJwk>, AppError> {
        Ok(vec![])
    }
}

fn test_key_jwk_generator() -> Arc<dyn KeyJwkGenerator> {
    Arc::new(TestKeyJwkGenerator)
}

fn rsa_pss_key_for_algorithm(alg: &str) -> Option<AsymmetricKeyData> {
    let (hash, salt_len) = match alg {
        "PS256" => (josekit::util::SHA_256, 32),
        "PS384" => (josekit::util::SHA_384, 48),
        "PS512" => (josekit::util::SHA_512, 64),
        _ => return None,
    };
    let key_pair =
        josekit::jwk::alg::rsapss::RsaPssKeyPair::generate(2048, hash, hash, salt_len).unwrap();

    Some(AsymmetricKeyData {
        private_key: String::from_utf8(key_pair.to_pem_private_key()).unwrap(),
        public_key: String::from_utf8(key_pair.to_pem_public_key()).unwrap(),
        certificate: None,
    })
}

fn decode_jwt_with_alg(token: &str, public_key_pem: &str, alg: &str) -> JwtPayload {
    let public_key = public_key_pem.as_bytes();
    match alg {
        "RS256" => jwt::decode_with_verifier(token, &*RS256.verifier_from_pem(public_key).unwrap()),
        "RS384" => jwt::decode_with_verifier(token, &*RS384.verifier_from_pem(public_key).unwrap()),
        "RS512" => jwt::decode_with_verifier(token, &*RS512.verifier_from_pem(public_key).unwrap()),
        "PS256" => jwt::decode_with_verifier(token, &*PS256.verifier_from_pem(public_key).unwrap()),
        "PS384" => jwt::decode_with_verifier(token, &*PS384.verifier_from_pem(public_key).unwrap()),
        "PS512" => jwt::decode_with_verifier(token, &*PS512.verifier_from_pem(public_key).unwrap()),
        "ES256" => jwt::decode_with_verifier(token, &*ES256.verifier_from_pem(public_key).unwrap()),
        "ES384" => jwt::decode_with_verifier(token, &*ES384.verifier_from_pem(public_key).unwrap()),
        "ES512" => jwt::decode_with_verifier(token, &*ES512.verifier_from_pem(public_key).unwrap()),
        "ES256K" => {
            jwt::decode_with_verifier(token, &*ES256K.verifier_from_pem(public_key).unwrap())
        }
        "EdDSA" => jwt::decode_with_verifier(token, &*EdDSA.verifier_from_pem(public_key).unwrap()),
        other => panic!("unsupported test alg: {other}"),
    }
    .unwrap()
    .0
}

fn build_token_service_with_key(
    repo: Arc<MockClientAuthorizationRepository>,
    key: Key,
    user_oid: Uuid,
) -> TokenService {
    let binding = key_jwk_binding(&key, &key_data_algorithm(&key), Uuid::new_v4());
    TokenService::new(
        repo,
        Arc::new(key_repo_with_keys(vec![key.clone()])),
        Arc::new(jwk_repo_with_bindings(vec![binding])),
        Arc::new(InMemoryUserRepository {
            user: test_user(user_oid),
        }),
        Arc::new(InMemoryClientRepository),
        Arc::new(cred_repo_with(vec![OpenIdConnectCredential {
            oid: Uuid::new_v4(),
            client_oid: Uuid::nil(),
            r#type: OpenIdConnectCredentialType::ClientSecret,
            hint: "token".to_string(),
            data: OpenIdConnectCredentialData::ClientSecret {
                secret: "secret-123".to_string(),
            },
            expires_at: Utc::now() + chrono::Duration::days(1),
            revoked_at: None,
            created_at: Utc::now(),
            updated_at: None,
        }])),
        provider_service(),
        signing_algorithm_detector(),
        InMemoryDataProtector::new(),
    )
}

fn key_data_algorithm(key: &Key) -> String {
    match &key.data {
        KeyData::Asymmetric(data) => data
            .certificate
            .clone()
            .unwrap_or_else(|| "RS256".to_owned()),
        KeyData::Symmetric(_) => "RS256".to_owned(),
    }
}

fn user_info_service_with_key(
    repo: Arc<MockClientAuthorizationRepository>,
    key: Key,
    user_oid: Uuid,
) -> crate::openid_connect::user_info::UserInfoService {
    crate::openid_connect::user_info::UserInfoService::new(
        Arc::new(InMemoryUserRepository {
            user: test_user(user_oid),
        }),
        Arc::new(InMemoryClientRepository),
        repo,
        Arc::new(AsymmetricKeyService::new(
            Arc::new(key_repo_with_keys(vec![key])),
            Arc::new(TestAsymmetricKeyGenerator),
            test_key_jwk_generator(),
            None,
        )),
        provider_service(),
    )
}

fn test_user(user_oid: Uuid) -> User {
    User {
        oid: UserOid(user_oid),
        email: "alg@example.com".to_string(),
        email_normalized: "alg@example.com".to_string(),
        name: "Alg User".to_string(),
        name_normalized: "alg user".to_string(),
        given_name: None,
        family_name: None,
        middle_name: None,
        nickname: None,
        profile: None,
        picture: None,
        website: None,
        gender: None,
        birthdate: None,
        zoneinfo: None,
        locale: None,
        email_verified: true,
        phone_number: None,
        phone_number_verified: None,
        address_formatted: None,
        address_street_address: None,
        address_locality: None,
        address_region: None,
        address_postal_code: None,
        address_country: None,
        failed_attempts: 0,
        enabled: true,
        locked: false,
        locked_until: None,
        created_at: Utc::now(),
        updated_at: None,
    }
}

#[test]
fn expected_at_hash_uses_sha256_for_256_bit_algs() {
    let token = "access-token";
    let digest = Sha256::digest(token.as_bytes());

    assert_eq!(
        expected_at_hash_for_alg(token, "RS256"),
        URL_SAFE_NO_PAD.encode(&digest[..16])
    );
    assert_eq!(
        expected_at_hash_for_alg(token, "PS256"),
        URL_SAFE_NO_PAD.encode(&digest[..16])
    );
    assert_eq!(
        expected_at_hash_for_alg(token, "ES256K"),
        URL_SAFE_NO_PAD.encode(&digest[..16])
    );
}

#[test]
fn expected_at_hash_uses_sha384_for_384_bit_algs() {
    let token = "access-token";
    let digest = Sha384::digest(token.as_bytes());

    assert_eq!(
        expected_at_hash_for_alg(token, "RS384"),
        URL_SAFE_NO_PAD.encode(&digest[..24])
    );
    assert_eq!(
        expected_at_hash_for_alg(token, "PS384"),
        URL_SAFE_NO_PAD.encode(&digest[..24])
    );
    assert_eq!(
        expected_at_hash_for_alg(token, "ES384"),
        URL_SAFE_NO_PAD.encode(&digest[..24])
    );
}

#[test]
fn expected_at_hash_uses_sha512_for_512_bit_and_eddsa_algs() {
    let token = "access-token";
    let digest = Sha512::digest(token.as_bytes());

    assert_eq!(
        expected_at_hash_for_alg(token, "RS512"),
        URL_SAFE_NO_PAD.encode(&digest[..32])
    );
    assert_eq!(
        expected_at_hash_for_alg(token, "PS512"),
        URL_SAFE_NO_PAD.encode(&digest[..32])
    );
    assert_eq!(
        expected_at_hash_for_alg(token, "EdDSA"),
        URL_SAFE_NO_PAD.encode(&digest[..32])
    );
}

#[test]
fn key_jwk_binding_uses_ec_shape_for_es256_keys() {
    let key = key_for_algorithm("ES256");
    let binding = key_jwk_binding(&key, "ES256", Uuid::new_v4());
    let jwk = serde_json::to_value(binding.jwk).unwrap();

    assert_eq!(jwk["kty"], serde_json::json!("EC"));
    assert_eq!(jwk["crv"], serde_json::json!("P-256"));
    assert_eq!(jwk["alg"], serde_json::json!("ES256"));
    assert_eq!(jwk["use"], serde_json::json!("sig"));
    assert!(jwk.get("x").is_some());
    assert!(jwk.get("y").is_some());
}

#[test]
fn key_jwk_binding_uses_okp_shape_for_eddsa_keys() {
    let key = key_for_algorithm("EdDSA");
    let binding = key_jwk_binding(&key, "EdDSA", Uuid::new_v4());
    let jwk = serde_json::to_value(binding.jwk).unwrap();

    assert_eq!(jwk["kty"], serde_json::json!("OKP"));
    assert_eq!(jwk["crv"], serde_json::json!("Ed25519"));
    assert_eq!(jwk["alg"], serde_json::json!("EdDSA"));
    assert_eq!(jwk["use"], serde_json::json!("sig"));
    assert!(jwk.get("x").is_some());
}
