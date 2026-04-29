use crate::crypto::certificate::generate_self_signed_certificate;
use crate::crypto::key::{
    base64url_encode, generate_all_jwks_for_key, generate_ed25519_key, generate_p256_key,
    generate_rsa_key, public_jwk_from_private_key_pem,
};
use identity_domain::key::JwaSigningAlgorithm;
use identity_domain::key::model::AsymmetricKeyAlgorithm;
use josekit::jws::{
    ES256, ES256K, ES384, ES512, EdDSA, JwsHeader, PS256, PS384, PS512, RS256, RS384, RS512,
};
use josekit::jwt;

/// Generates a minimal RSA 2048 key PEM and a self-signed cert PEM for testing.
fn test_rsa_key_and_cert() -> (String, String) {
    let data = generate_rsa_key(2048).unwrap();
    let cert = generate_self_signed_certificate(
        &data.private_key,
        "test.example.com",
        &AsymmetricKeyAlgorithm::Rsa { bits: 2048 },
    )
    .unwrap();
    (data.private_key, cert)
}

#[test]
fn jwk_without_certificate_has_no_x5_fields() {
    let (private_key, _cert) = test_rsa_key_and_cert();
    let jwk = public_jwk_from_private_key_pem(&private_key, None, None).unwrap();
    assert!(jwk.parameter("x5c").is_none());
    assert!(jwk.parameter("x5t").is_none());
    assert!(jwk.parameter("x5t#S256").is_none());
}

#[test]
fn jwk_with_certificate_has_x5c_x5t_x5t_s256() {
    let (private_key, cert) = test_rsa_key_and_cert();
    let jwk = public_jwk_from_private_key_pem(&private_key, None, Some(&cert)).unwrap();

    // x5c must be a non-empty array
    let x5c = jwk.parameter("x5c").expect("x5c missing");
    assert!(x5c.is_array(), "x5c must be a JSON array");
    let arr = x5c.as_array().unwrap();
    assert_eq!(arr.len(), 1, "x5c must have exactly one element");
    assert!(arr[0].is_string(), "x5c[0] must be a string");

    // x5t must be a non-empty string
    let x5t = jwk.parameter("x5t").expect("x5t missing");
    assert!(x5t.is_string());
    assert!(!x5t.as_str().unwrap().is_empty());

    // x5t#S256 must be a non-empty string
    let x5t_s256 = jwk.parameter("x5t#S256").expect("x5t#S256 missing");
    assert!(x5t_s256.is_string());
    assert!(!x5t_s256.as_str().unwrap().is_empty());
}

#[test]
fn x5t_s256_matches_sha256_of_der() {
    use openssl::hash::{MessageDigest, hash};
    use openssl::x509::X509;

    let (private_key, cert_pem) = test_rsa_key_and_cert();
    let jwk = public_jwk_from_private_key_pem(&private_key, None, Some(&cert_pem)).unwrap();

    // Independently compute expected x5t#S256
    let x509 = X509::from_pem(cert_pem.as_bytes()).unwrap();
    let der = x509.to_der().unwrap();
    let digest = hash(MessageDigest::sha256(), &der).unwrap();
    let expected = base64url_encode(&digest);

    let actual = jwk
        .parameter("x5t#S256")
        .unwrap()
        .as_str()
        .unwrap()
        .to_owned();
    assert_eq!(actual, expected);
}

#[test]
fn x5t_matches_sha1_of_der() {
    use openssl::hash::{MessageDigest, hash};
    use openssl::x509::X509;

    let (private_key, cert_pem) = test_rsa_key_and_cert();
    let jwk = public_jwk_from_private_key_pem(&private_key, None, Some(&cert_pem)).unwrap();

    let x509 = X509::from_pem(cert_pem.as_bytes()).unwrap();
    let der = x509.to_der().unwrap();
    let digest = hash(MessageDigest::sha1(), &der).unwrap();
    let expected = base64url_encode(&digest);

    let actual = jwk.parameter("x5t").unwrap().as_str().unwrap().to_owned();
    assert_eq!(actual, expected);
}

#[test]
fn x5c_matches_base64_standard_of_der() {
    use openssl::base64::encode_block;
    use openssl::x509::X509;

    let (private_key, cert_pem) = test_rsa_key_and_cert();
    let jwk = public_jwk_from_private_key_pem(&private_key, None, Some(&cert_pem)).unwrap();

    let x509 = X509::from_pem(cert_pem.as_bytes()).unwrap();
    let der = x509.to_der().unwrap();
    let expected = encode_block(&der);

    let actual = jwk.parameter("x5c").unwrap().as_array().unwrap()[0]
        .as_str()
        .unwrap()
        .to_owned();
    assert_eq!(actual, expected);
}

#[test]
fn generate_all_jwks_for_rsa_key_produces_rs_jwks() {
    let data = generate_rsa_key(2048).unwrap();
    let jwks = generate_all_jwks_for_key(&data.private_key, "kid-rsa", None).unwrap();
    assert_eq!(jwks.len(), 3);
    let algs: Vec<&str> = jwks.iter().map(|(alg, _)| alg.as_str()).collect();
    assert!(algs.contains(&"RS256"));
    assert!(algs.contains(&"RS384"));
    assert!(algs.contains(&"RS512"));
    assert!(!algs.contains(&"PS256"));
    assert!(!algs.contains(&"PS384"));
    assert!(!algs.contains(&"PS512"));
}

#[test]
fn generate_all_jwks_for_rsa_pss_key_produces_ps_jwk() {
    let key_pair = josekit::jwk::alg::rsapss::RsaPssKeyPair::generate(
        2048,
        josekit::util::SHA_256,
        josekit::util::SHA_256,
        32,
    )
    .unwrap();
    let private_key = String::from_utf8(key_pair.to_pem_private_key()).unwrap();

    let jwks = generate_all_jwks_for_key(&private_key, "kid-ps", None).unwrap();

    assert_eq!(jwks.len(), 1);
    assert_eq!(jwks[0].0, "PS256");
    assert_eq!(jwks[0].1.algorithm().unwrap(), "PS256");
    assert_eq!(jwks[0].1.key_id().unwrap(), "kid-ps");
}

#[test]
fn generate_all_jwks_for_rsa_key_sets_kid_on_each_jwk() {
    let data = generate_rsa_key(2048).unwrap();
    let jwks = generate_all_jwks_for_key(&data.private_key, "kid-rsa", None).unwrap();
    for (_, jwk) in &jwks {
        assert_eq!(
            jwk.key_id().unwrap(),
            "kid-rsa",
            "kid should be set on JWK with alg {}",
            jwk.algorithm().unwrap_or("none")
        );
    }
}

#[test]
fn generate_all_jwks_for_ec_p256_key_produces_one_jwk() {
    let data = generate_p256_key().unwrap();
    let jwks = generate_all_jwks_for_key(&data.private_key, "kid-ec", None).unwrap();
    assert_eq!(jwks.len(), 1);
    assert_eq!(jwks[0].0, "ES256");
    assert_eq!(jwks[0].1.algorithm().unwrap(), "ES256");
}

#[test]
fn generate_all_jwks_for_ed25519_key_produces_one_jwk() {
    let data = generate_ed25519_key().unwrap();
    let jwks = generate_all_jwks_for_key(&data.private_key, "kid-ed", None).unwrap();
    assert_eq!(jwks.len(), 1);
    assert_eq!(jwks[0].0, "EdDSA");
}

#[track_caller]
fn assert_roundtrip(private_key_pem: &str, public_key_pem: &str, alg_label: &str) {
    let jwa: JwaSigningAlgorithm = alg_label.parse().unwrap();
    let pem = private_key_pem.as_bytes();

    let signer: Box<dyn josekit::jws::JwsSigner> = match jwa {
        JwaSigningAlgorithm::Rs256 => Box::new(RS256.signer_from_pem(pem).unwrap()),
        JwaSigningAlgorithm::Rs384 => Box::new(RS384.signer_from_pem(pem).unwrap()),
        JwaSigningAlgorithm::Rs512 => Box::new(RS512.signer_from_pem(pem).unwrap()),
        JwaSigningAlgorithm::Ps256 => Box::new(PS256.signer_from_pem(pem).unwrap()),
        JwaSigningAlgorithm::Ps384 => Box::new(PS384.signer_from_pem(pem).unwrap()),
        JwaSigningAlgorithm::Ps512 => Box::new(PS512.signer_from_pem(pem).unwrap()),
        JwaSigningAlgorithm::Es256 => Box::new(ES256.signer_from_pem(pem).unwrap()),
        JwaSigningAlgorithm::Es384 => Box::new(ES384.signer_from_pem(pem).unwrap()),
        JwaSigningAlgorithm::Es512 => Box::new(ES512.signer_from_pem(pem).unwrap()),
        JwaSigningAlgorithm::Es256k => Box::new(ES256K.signer_from_pem(pem).unwrap()),
        JwaSigningAlgorithm::EdDsa => Box::new(EdDSA.signer_from_pem(pem).unwrap()),
    };

    let mut header = JwsHeader::new();
    header.set_algorithm(alg_label);
    let mut payload = jwt::JwtPayload::new();
    payload.set_subject("test-user");
    payload
        .set_claim("alg", Some(serde_json::json!(alg_label)))
        .unwrap();

    let token = jwt::encode_with_signer(&payload, &header, &*signer).unwrap();

    let public_pem = public_key_pem.as_bytes();
    let (decoded, _) = match jwa {
        JwaSigningAlgorithm::Rs256 => {
            let v = RS256.verifier_from_pem(public_pem).unwrap();
            jwt::decode_with_verifier(&token, &v).unwrap()
        }
        JwaSigningAlgorithm::Rs384 => {
            let v = RS384.verifier_from_pem(public_pem).unwrap();
            jwt::decode_with_verifier(&token, &v).unwrap()
        }
        JwaSigningAlgorithm::Rs512 => {
            let v = RS512.verifier_from_pem(public_pem).unwrap();
            jwt::decode_with_verifier(&token, &v).unwrap()
        }
        JwaSigningAlgorithm::Ps256 => {
            let v = PS256.verifier_from_pem(public_pem).unwrap();
            jwt::decode_with_verifier(&token, &v).unwrap()
        }
        JwaSigningAlgorithm::Ps384 => {
            let v = PS384.verifier_from_pem(public_pem).unwrap();
            jwt::decode_with_verifier(&token, &v).unwrap()
        }
        JwaSigningAlgorithm::Ps512 => {
            let v = PS512.verifier_from_pem(public_pem).unwrap();
            jwt::decode_with_verifier(&token, &v).unwrap()
        }
        JwaSigningAlgorithm::Es256 => {
            let v = ES256.verifier_from_pem(public_pem).unwrap();
            jwt::decode_with_verifier(&token, &v).unwrap()
        }
        JwaSigningAlgorithm::Es384 => {
            let v = ES384.verifier_from_pem(public_pem).unwrap();
            jwt::decode_with_verifier(&token, &v).unwrap()
        }
        JwaSigningAlgorithm::Es512 => {
            let v = ES512.verifier_from_pem(public_pem).unwrap();
            jwt::decode_with_verifier(&token, &v).unwrap()
        }
        JwaSigningAlgorithm::Es256k => {
            let v = ES256K.verifier_from_pem(public_pem).unwrap();
            jwt::decode_with_verifier(&token, &v).unwrap()
        }
        JwaSigningAlgorithm::EdDsa => {
            let v = EdDSA.verifier_from_pem(public_pem).unwrap();
            jwt::decode_with_verifier(&token, &v).unwrap()
        }
    };

    assert_eq!(
        decoded.subject().unwrap(),
        "test-user",
        "roundtrip failed for {alg_label}"
    );
    assert_eq!(
        decoded.claim("alg").and_then(|v| v.as_str()),
        Some(alg_label),
        "alg claim mismatch for {alg_label}"
    );
}

#[test]
fn rs256_roundtrip() {
    let data = generate_rsa_key(2048).unwrap();
    assert_roundtrip(&data.private_key, &data.public_key, "RS256");
}

#[test]
fn rs384_roundtrip() {
    let data = generate_rsa_key(3072).unwrap();
    assert_roundtrip(&data.private_key, &data.public_key, "RS384");
}

#[test]
fn rs512_roundtrip() {
    let data = generate_rsa_key(4096).unwrap();
    assert_roundtrip(&data.private_key, &data.public_key, "RS512");
}

#[test]
fn ps256_roundtrip() {
    let key_pair = josekit::jwk::alg::rsapss::RsaPssKeyPair::generate(
        2048,
        josekit::util::SHA_256,
        josekit::util::SHA_256,
        32,
    )
    .unwrap();
    let private = String::from_utf8(key_pair.to_pem_private_key()).unwrap();
    let public_pem = String::from_utf8(key_pair.to_pem_public_key()).unwrap();
    assert_roundtrip(&private, &public_pem, "PS256");
}

#[test]
fn ps384_roundtrip() {
    let key_pair = josekit::jwk::alg::rsapss::RsaPssKeyPair::generate(
        2048,
        josekit::util::SHA_384,
        josekit::util::SHA_384,
        48,
    )
    .unwrap();
    let private = String::from_utf8(key_pair.to_pem_private_key()).unwrap();
    let public_pem = String::from_utf8(key_pair.to_pem_public_key()).unwrap();
    assert_roundtrip(&private, &public_pem, "PS384");
}

#[test]
fn ps512_roundtrip() {
    let key_pair = josekit::jwk::alg::rsapss::RsaPssKeyPair::generate(
        2048,
        josekit::util::SHA_512,
        josekit::util::SHA_512,
        64,
    )
    .unwrap();
    let private = String::from_utf8(key_pair.to_pem_private_key()).unwrap();
    let public_pem = String::from_utf8(key_pair.to_pem_public_key()).unwrap();
    assert_roundtrip(&private, &public_pem, "PS512");
}

#[test]
fn es256_roundtrip() {
    let data = generate_p256_key().unwrap();
    assert_roundtrip(&data.private_key, &data.public_key, "ES256");
}

#[test]
fn es384_roundtrip() {
    let jwk = josekit::jwk::Jwk::generate_ec_key(josekit::jwk::alg::ec::EcCurve::P384).unwrap();
    let key_pair = josekit::jwk::alg::ec::EcKeyPair::from_jwk(&jwk).unwrap();
    let private = String::from_utf8(key_pair.to_pem_private_key()).unwrap();
    let public = String::from_utf8(key_pair.to_pem_public_key()).unwrap();
    assert_roundtrip(&private, &public, "ES384");
}

#[test]
fn es512_roundtrip() {
    let jwk = josekit::jwk::Jwk::generate_ec_key(josekit::jwk::alg::ec::EcCurve::P521).unwrap();
    let key_pair = josekit::jwk::alg::ec::EcKeyPair::from_jwk(&jwk).unwrap();
    let private = String::from_utf8(key_pair.to_pem_private_key()).unwrap();
    let public = String::from_utf8(key_pair.to_pem_public_key()).unwrap();
    assert_roundtrip(&private, &public, "ES512");
}

#[test]
fn es256k_roundtrip() {
    let jwk =
        josekit::jwk::Jwk::generate_ec_key(josekit::jwk::alg::ec::EcCurve::Secp256k1).unwrap();
    let key_pair = josekit::jwk::alg::ec::EcKeyPair::from_jwk(&jwk).unwrap();
    let private = String::from_utf8(key_pair.to_pem_private_key()).unwrap();
    let public = String::from_utf8(key_pair.to_pem_public_key()).unwrap();
    assert_roundtrip(&private, &public, "ES256K");
}

#[test]
fn eddsa_roundtrip() {
    let data = generate_ed25519_key().unwrap();
    assert_roundtrip(&data.private_key, &data.public_key, "EdDSA");
}
