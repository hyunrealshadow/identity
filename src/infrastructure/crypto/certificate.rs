use std::error::Error;

use identity_domain::key::{generator::KeyMaterialError, model::AsymmetricKeyAlgorithm};
use josekit::{
    jwk::alg::rsapss::RsaPssKeyPair,
    jws::{PS256, PS384, PS512},
};
use openssl::{
    asn1::{Asn1Integer, Asn1Time},
    bn::{BigNum, MsbOption},
    hash::MessageDigest,
    pkey::PKey,
    x509::{
        X509, X509NameBuilder,
        extension::{BasicConstraints, KeyUsage, SubjectAlternativeName, SubjectKeyIdentifier},
    },
};
use url::Url;

fn internal<E>(error: E) -> KeyMaterialError
where
    E: Error + Send + Sync + 'static,
{
    KeyMaterialError::Internal(Box::new(error))
}

pub fn generate_self_signed_certificate(
    private_key_pem: &str,
    domain: &str,
    algorithm: &AsymmetricKeyAlgorithm,
) -> Result<String, KeyMaterialError> {
    let dns_name = certificate_dns_name(domain).ok_or_else(|| {
        KeyMaterialError::InvalidInput("certificate domain must contain a DNS hostname".to_owned())
    })?;
    let pkey = PKey::private_key_from_pem(private_key_pem.as_bytes()).map_err(internal)?;

    let mut name = X509NameBuilder::new().map_err(internal)?;
    name.append_entry_by_text("CN", &dns_name)
        .map_err(internal)?;
    let name = name.build();

    let mut serial = BigNum::new().map_err(internal)?;
    serial
        .rand(128, MsbOption::MAYBE_ZERO, false)
        .map_err(internal)?;
    let serial = Asn1Integer::from_bn(&serial).map_err(internal)?;
    let not_before = Asn1Time::days_from_now(0).map_err(internal)?;
    let not_after = Asn1Time::days_from_now(3650).map_err(internal)?;

    let mut builder = X509::builder().map_err(internal)?;
    builder.set_version(2).map_err(internal)?;
    builder.set_serial_number(&serial).map_err(internal)?;
    builder.set_subject_name(&name).map_err(internal)?;
    builder.set_issuer_name(&name).map_err(internal)?;
    builder.set_pubkey(&pkey).map_err(internal)?;
    builder.set_not_before(&not_before).map_err(internal)?;
    builder.set_not_after(&not_after).map_err(internal)?;

    let basic_constraints = BasicConstraints::new()
        .critical()
        .build()
        .map_err(internal)?;
    builder
        .append_extension(basic_constraints)
        .map_err(internal)?;

    let mut key_usage = KeyUsage::new();
    key_usage.critical();
    match algorithm {
        AsymmetricKeyAlgorithm::Rsa { .. } => {
            key_usage.digital_signature().key_encipherment();
        }
        AsymmetricKeyAlgorithm::EcdsaP256
        | AsymmetricKeyAlgorithm::EcdsaP384
        | AsymmetricKeyAlgorithm::EcdsaP521
        | AsymmetricKeyAlgorithm::EcdsaSecp256k1 => {
            key_usage.digital_signature().key_agreement();
        }
        AsymmetricKeyAlgorithm::Ed25519 | AsymmetricKeyAlgorithm::Ed448 => {
            key_usage.digital_signature();
        }
        AsymmetricKeyAlgorithm::X25519 | AsymmetricKeyAlgorithm::X448 => {
            key_usage.key_agreement();
        }
    }
    let key_usage = key_usage.build().map_err(internal)?;
    builder.append_extension(key_usage).map_err(internal)?;

    let subject_key_identifier = SubjectKeyIdentifier::new()
        .build(&builder.x509v3_context(None, None))
        .map_err(internal)?;
    builder
        .append_extension(subject_key_identifier)
        .map_err(internal)?;

    let subject_alt_name = SubjectAlternativeName::new()
        .dns(&dns_name)
        .build(&builder.x509v3_context(None, None))
        .map_err(internal)?;
    builder
        .append_extension(subject_alt_name)
        .map_err(internal)?;

    builder
        .sign(&pkey, certificate_digest(private_key_pem, algorithm)?)
        .map_err(internal)?;

    let certificate = builder.build().to_pem().map_err(internal)?;
    String::from_utf8(certificate).map_err(internal)
}

fn certificate_dns_name(domain: &str) -> Option<String> {
    let domain = domain.trim();
    let url = if domain.contains("://") {
        Url::parse(domain).ok()?
    } else {
        Url::parse(&format!("https://{domain}")).ok()?
    };
    let host = url.host_str()?.trim_end_matches('.');
    (!host.is_empty()).then(|| host.to_owned())
}

fn certificate_digest(
    private_key_pem: &str,
    algorithm: &AsymmetricKeyAlgorithm,
) -> Result<MessageDigest, KeyMaterialError> {
    if matches!(algorithm, AsymmetricKeyAlgorithm::Rsa { .. })
        && RsaPssKeyPair::from_pem(private_key_pem, None, None, None).is_ok()
    {
        return if PS256.signer_from_pem(private_key_pem).is_ok() {
            Ok(MessageDigest::sha256())
        } else if PS384.signer_from_pem(private_key_pem).is_ok() {
            Ok(MessageDigest::sha384())
        } else if PS512.signer_from_pem(private_key_pem).is_ok() {
            Ok(MessageDigest::sha512())
        } else {
            Err(KeyMaterialError::InvalidInput(
                "unsupported RSA-PSS certificate signing digest".to_owned(),
            ))
        };
    }
    Ok(match algorithm {
        AsymmetricKeyAlgorithm::Ed25519 | AsymmetricKeyAlgorithm::Ed448 => MessageDigest::null(),
        AsymmetricKeyAlgorithm::EcdsaP384 => MessageDigest::sha384(),
        AsymmetricKeyAlgorithm::EcdsaP521 => MessageDigest::sha512(),
        AsymmetricKeyAlgorithm::Rsa { bits } if *bits >= 4096 => MessageDigest::sha512(),
        _ => MessageDigest::sha256(),
    })
}
