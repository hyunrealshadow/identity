//! Reads the public keys clients register for `private_key_jwt`.
//!
//! A key is accepted when the same josekit verifiers that check client
//! assertions can be built from it, so registration and verification never
//! disagree about what a usable key is. A certificate is reduced to its public
//! key and contributes its `notAfter` as the credential expiry.

use base64::{
    Engine as _,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use chrono::{DateTime, TimeZone, Utc};
use identity_application::{
    client::{
        MAX_PUBLIC_KEY_INPUT_LENGTH,
        public_key::{ClientPublicKeyReader, PublicKeyError, PublicKeyMaterial, ReadPublicKey},
    },
    openid_connect::jose::{asymmetric_verifier_from_pem, asymmetric_verifier_from_public_jwk},
};
use identity_domain::key::PublicJwk;
use openssl::{
    asn1::{Asn1Time, Asn1TimeRef},
    x509::X509,
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

/// Signing algorithms tried when deciding whether a key is usable at all.
const ASSERTION_ALGORITHMS: [&str; 8] = [
    "RS256", "PS256", "ES256", "ES384", "ES512", "ES256K", "EdDSA", "RS512",
];

/// JWK members that only a private or symmetric key carries.
const PRIVATE_JWK_MEMBERS: [&str; 8] = ["d", "p", "q", "dp", "dq", "qi", "oth", "k"];

pub struct ClientPublicKeyReaderImpl;

impl ClientPublicKeyReader for ClientPublicKeyReaderImpl {
    fn read(&self, input: &str) -> Result<ReadPublicKey, PublicKeyError> {
        read_public_key(input)
    }
}

fn read_public_key(input: &str) -> Result<ReadPublicKey, PublicKeyError> {
    let input = input.trim();
    if input.is_empty() || input.len() > MAX_PUBLIC_KEY_INPUT_LENGTH {
        return Err(PublicKeyError::Length);
    }
    if input.contains("PRIVATE KEY") {
        return Err(PublicKeyError::Private);
    }
    if input.starts_with('{') {
        let jwk = parse_jwk(input)?;
        let hint = jwk
            .key_id()
            .map_or_else(|| jwk_thumbprint(&jwk), ToOwned::to_owned);
        return Ok(ReadPublicKey {
            material: PublicKeyMaterial::Jwk(jwk),
            hint,
            certificate_expiry: None,
        });
    }

    let (pem, certificate_expiry) = if input.contains("-----BEGIN CERTIFICATE-----") {
        // josekit verifies with bare keys only, so take the certificate's key.
        let certificate = X509::from_pem(input.as_bytes()).map_err(|_| PublicKeyError::Unusable)?;
        let expiry = asn1_to_utc(certificate.not_after())?;
        if expiry <= Utc::now() {
            return Err(PublicKeyError::CertificateExpired);
        }
        let pem = certificate
            .public_key()
            .and_then(|key| key.public_key_to_pem())
            .ok()
            .and_then(|pem| String::from_utf8(pem).ok())
            .ok_or(PublicKeyError::Unusable)?;
        (pem.trim().to_owned(), Some(expiry))
    } else {
        (input.to_owned(), None)
    };
    if !ASSERTION_ALGORITHMS
        .iter()
        .any(|alg| asymmetric_verifier_from_pem(alg, pem.as_bytes()).is_ok())
    {
        return Err(PublicKeyError::Unusable);
    }
    Ok(ReadPublicKey {
        hint: pem_fingerprint(&pem)?,
        material: PublicKeyMaterial::Pem(pem),
        certificate_expiry,
    })
}

fn parse_jwk(input: &str) -> Result<PublicJwk, PublicKeyError> {
    let value: Value = serde_json::from_str(input).map_err(|_| PublicKeyError::Unusable)?;
    let object = value.as_object().ok_or(PublicKeyError::Unusable)?;
    if PRIVATE_JWK_MEMBERS
        .iter()
        .any(|member| object.contains_key(*member))
    {
        return Err(PublicKeyError::Private);
    }
    let jwk: PublicJwk = serde_json::from_value(value).map_err(|_| PublicKeyError::Unusable)?;
    let usable = match jwk.algorithm() {
        Some(alg) => asymmetric_verifier_from_public_jwk(alg, &jwk).is_ok(),
        None => ASSERTION_ALGORITHMS
            .iter()
            .any(|alg| asymmetric_verifier_from_public_jwk(alg, &jwk).is_ok()),
    };
    if !usable {
        return Err(PublicKeyError::Unusable);
    }
    Ok(jwk)
}

/// RFC 7638: SHA-256 over the required members in lexicographic order.
fn jwk_thumbprint(jwk: &PublicJwk) -> String {
    let members = match jwk {
        PublicJwk::Rsa { n, e, .. } => json!({ "e": e, "kty": "RSA", "n": n }),
        PublicJwk::Ec { crv, x, y, .. } => json!({ "crv": crv, "kty": "EC", "x": x, "y": y }),
        PublicJwk::Okp { crv, x, .. } => json!({ "crv": crv, "kty": "OKP", "x": x }),
    };
    // `serde_json` keeps object keys sorted, which RFC 7638 requires.
    URL_SAFE_NO_PAD.encode(Sha256::digest(members.to_string().as_bytes()))
}

/// SHA-256 of the DER inside a PEM block.
fn pem_fingerprint(pem: &str) -> Result<String, PublicKeyError> {
    let body: String = pem
        .lines()
        .filter(|line| !line.starts_with("-----"))
        .flat_map(|line| line.trim().chars())
        .collect();
    let der = STANDARD
        .decode(body)
        .map_err(|_| PublicKeyError::Unusable)?;
    Ok(URL_SAFE_NO_PAD.encode(Sha256::digest(der)))
}

fn asn1_to_utc(time: &Asn1TimeRef) -> Result<DateTime<Utc>, PublicKeyError> {
    let epoch = Asn1Time::from_unix(0).map_err(|_| PublicKeyError::Unusable)?;
    let diff = epoch.diff(time).map_err(|_| PublicKeyError::Unusable)?;
    let seconds = i64::from(diff.days) * 86_400 + i64::from(diff.secs);
    Utc.timestamp_opt(seconds, 0)
        .single()
        .ok_or(PublicKeyError::Unusable)
}

#[cfg(test)]
mod tests {
    use openssl::{
        asn1::Asn1Time,
        ec::{EcGroup, EcKey},
        hash::MessageDigest,
        nid::Nid,
        pkey::{PKey, Private},
        rsa::Rsa,
        x509::{X509, X509NameBuilder},
    };
    use serde_json::json;

    use identity_application::client::public_key::{PublicKeyError, PublicKeyMaterial};

    use super::read_public_key as parse_public_key;

    fn rsa_key(bits: u32) -> PKey<Private> {
        PKey::from_rsa(Rsa::generate(bits).unwrap()).unwrap()
    }

    fn public_pem(key: &PKey<Private>) -> String {
        String::from_utf8(key.public_key_to_pem().unwrap()).unwrap()
    }

    fn certificate(key: &PKey<Private>, not_after_days: u32) -> String {
        let mut name = X509NameBuilder::new().unwrap();
        name.append_entry_by_text("CN", "client.example").unwrap();
        let name = name.build();
        let mut builder = X509::builder().unwrap();
        builder.set_version(2).unwrap();
        builder.set_subject_name(&name).unwrap();
        builder.set_issuer_name(&name).unwrap();
        builder.set_pubkey(key).unwrap();
        builder
            .set_not_before(&Asn1Time::days_from_now(0).unwrap())
            .unwrap();
        builder
            .set_not_after(&Asn1Time::days_from_now(not_after_days).unwrap())
            .unwrap();
        builder.sign(key, MessageDigest::sha256()).unwrap();
        String::from_utf8(builder.build().to_pem().unwrap()).unwrap()
    }

    #[test]
    fn a_certificate_yields_its_key_and_expiry() {
        let key = rsa_key(2048);
        let bare = parse_public_key(&public_pem(&key)).unwrap();
        let certificate = parse_public_key(&certificate(&key, 30)).unwrap();

        assert_eq!(bare.material, certificate.material);
        assert_eq!(bare.hint, certificate.hint);
        assert!(bare.certificate_expiry.is_none());
        assert!(certificate.certificate_expiry.is_some());
    }

    #[test]
    fn a_jwk_keeps_its_kid_and_falls_back_to_the_rfc_7638_thumbprint() {
        // RFC 7638 section 3.1.
        let mut jwk = json!({
            "kty": "RSA",
            "n": "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
            "e": "AQAB",
            "alg": "RS256",
            "kid": "2011-04-29"
        });
        let with_kid = parse_public_key(&jwk.to_string()).unwrap();
        assert_eq!(with_kid.hint, "2011-04-29");
        assert!(matches!(with_kid.material, PublicKeyMaterial::Jwk(_)));

        jwk.as_object_mut().unwrap().remove("kid");
        let without_kid = parse_public_key(&jwk.to_string()).unwrap();
        assert_eq!(
            without_kid.hint,
            "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs"
        );
    }

    #[test]
    fn ec_and_pkcs1_pem_keys_are_accepted() {
        let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
        let ec = PKey::from_ec_key(EcKey::generate(&group).unwrap()).unwrap();
        assert!(parse_public_key(&public_pem(&ec)).is_ok());

        let rsa = Rsa::generate(2048).unwrap();
        let pkcs1 = String::from_utf8(rsa.public_key_to_pem_pkcs1().unwrap()).unwrap();
        assert!(parse_public_key(&pkcs1).is_ok());
    }

    #[test]
    fn private_weak_expired_and_malformed_keys_are_rejected() {
        let key = rsa_key(2048);
        let private = String::from_utf8(key.private_key_to_pem_pkcs8().unwrap()).unwrap();
        assert_eq!(parse_public_key(&private), Err(PublicKeyError::Private));
        assert_eq!(
            parse_public_key(&json!({"kty": "oct", "k": "c2VjcmV0"}).to_string()),
            Err(PublicKeyError::Private)
        );
        assert_eq!(
            parse_public_key(
                &json!({"kty": "RSA", "n": "AQAB", "e": "AQAB", "d": "AQAB"}).to_string()
            ),
            Err(PublicKeyError::Private)
        );
        assert_eq!(
            parse_public_key(&public_pem(&rsa_key(1024))),
            Err(PublicKeyError::Unusable)
        );
        assert_eq!(
            parse_public_key(&certificate(&key, 0)).err(),
            Some(PublicKeyError::CertificateExpired)
        );
        assert_eq!(parse_public_key("   "), Err(PublicKeyError::Length));
        assert_eq!(
            parse_public_key("-----BEGIN PUBLIC KEY-----\nAAAA\n-----END PUBLIC KEY-----"),
            Err(PublicKeyError::Unusable)
        );
    }
}
