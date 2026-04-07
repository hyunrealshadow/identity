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

use crate::domain::key::{generator::KeyMaterialError, model::AsymmetricKeyAlgorithm};

fn internal<E>(error: E) -> KeyMaterialError
where
    E: std::error::Error + Send + Sync + 'static,
{
    KeyMaterialError::Internal(Box::new(error))
}

pub fn generate_self_signed_certificate(
    private_key_pem: &str,
    domain: &str,
    algorithm: &AsymmetricKeyAlgorithm,
) -> Result<String, KeyMaterialError> {
    let domain = domain.trim().trim_matches('.');
    if domain.is_empty() {
        return Err(KeyMaterialError::InvalidInput(
            "certificate domain is required".to_owned(),
        ));
    }

    let pkey = PKey::private_key_from_pem(private_key_pem.as_bytes()).map_err(internal)?;

    let mut name = X509NameBuilder::new().map_err(internal)?;
    name.append_entry_by_text("CN", domain).map_err(internal)?;
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

    let key_usage = KeyUsage::new()
        .critical()
        .digital_signature()
        .key_encipherment()
        .build()
        .map_err(internal)?;
    builder.append_extension(key_usage).map_err(internal)?;

    let subject_key_identifier = SubjectKeyIdentifier::new()
        .build(&builder.x509v3_context(None, None))
        .map_err(internal)?;
    builder
        .append_extension(subject_key_identifier)
        .map_err(internal)?;

    let subject_alt_name = SubjectAlternativeName::new()
        .dns(domain)
        .build(&builder.x509v3_context(None, None))
        .map_err(internal)?;
    builder
        .append_extension(subject_alt_name)
        .map_err(internal)?;

    builder
        .sign(&pkey, certificate_digest(algorithm))
        .map_err(internal)?;

    let certificate = builder.build().to_pem().map_err(internal)?;
    String::from_utf8(certificate).map_err(internal)
}

fn certificate_digest(algorithm: &AsymmetricKeyAlgorithm) -> MessageDigest {
    match algorithm {
        AsymmetricKeyAlgorithm::Ed25519 | AsymmetricKeyAlgorithm::Ed448 => MessageDigest::null(),
        AsymmetricKeyAlgorithm::EcdsaP384 => MessageDigest::sha384(),
        AsymmetricKeyAlgorithm::EcdsaP521 => MessageDigest::sha512(),
        AsymmetricKeyAlgorithm::Rsa { bits } if *bits >= 4096 => MessageDigest::sha512(),
        _ => MessageDigest::sha256(),
    }
}
