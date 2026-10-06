use base64::{Engine as _, engine::general_purpose::STANDARD};
use identity_application::{
    error::{AppError, codes::common::CommonErrorCode},
    key::{
        asymmetric::KeyJwkGenerator,
        rotation::{KeyRotationMaterialGenerator, RotationMaterial},
    },
};
use identity_domain::key::{
    AsymmetricKeyAlgorithm, AsymmetricKeyData, Key, KeyData, SymmetricKeyData,
    generator::{AsymmetricKeyGenerator, AsymmetricKeySpec},
};
use josekit::{
    jwk::{KeyPair, alg::rsapss::RsaPssKeyPair},
    jws::{PS256, PS384, PS512},
    util::HashAlgorithm,
};
use openssl::{nid::Nid, x509::X509};
use rand::{RngExt, rng};
use uuid::Uuid;

use super::{
    certificate::generate_self_signed_certificate,
    key::{AsymmetricKeyGeneratorImpl, infer_algorithm_from_private_key_pem},
    key_jwk::KeyJwkGeneratorImpl,
};

pub struct KeyRotationMaterialGeneratorImpl;

impl KeyRotationMaterialGenerator for KeyRotationMaterialGeneratorImpl {
    fn generate(&self, previous: &Key) -> Result<RotationMaterial, AppError> {
        match &previous.data {
            KeyData::Asymmetric(previous_data) => {
                let (algorithm, mut next) = generate_same_algorithm(&previous_data.private_key)?;
                if let Some(certificate) = &previous_data.certificate {
                    let domain = certificate_domain(certificate)?;
                    next.certificate = Some(
                        generate_self_signed_certificate(&next.private_key, &domain, &algorithm)
                            .map_err(AppError::internal)?,
                    );
                }
                let jwks = KeyJwkGeneratorImpl.generate(
                    &next.private_key,
                    &Uuid::new_v4().to_string(),
                    next.certificate.as_deref(),
                )?;
                Ok(RotationMaterial {
                    data: KeyData::Asymmetric(next),
                    jwks,
                })
            }
            KeyData::Symmetric(previous_data) => {
                let mut key_bytes = [0u8; 32];
                rng().fill(&mut key_bytes);
                Ok(RotationMaterial {
                    data: KeyData::Symmetric(SymmetricKeyData {
                        key: STANDARD.encode(key_bytes),
                        algorithm: previous_data.algorithm,
                    }),
                    jwks: Vec::new(),
                })
            }
        }
    }
}

fn generate_same_algorithm(
    previous_private_key: &str,
) -> Result<(AsymmetricKeyAlgorithm, AsymmetricKeyData), AppError> {
    let internal = || AppError::from_code(CommonErrorCode::InternalError);
    if let Ok(previous) = RsaPssKeyPair::from_pem(previous_private_key, None, None, None) {
        let (hash, salt_len) = if PS256.signer_from_pem(previous_private_key).is_ok() {
            (HashAlgorithm::Sha256, 32)
        } else if PS384.signer_from_pem(previous_private_key).is_ok() {
            (HashAlgorithm::Sha384, 48)
        } else if PS512.signer_from_pem(previous_private_key).is_ok() {
            (HashAlgorithm::Sha512, 64)
        } else {
            return Err(internal());
        };
        let bits = previous.key_len() as usize * 8;
        let generated = RsaPssKeyPair::generate(bits as u32, hash, hash, salt_len)
            .map_err(|error| internal().with_source(error))?;
        let data = AsymmetricKeyData {
            private_key: String::from_utf8(generated.to_pem_private_key())
                .map_err(|error| internal().with_source(error))?,
            public_key: String::from_utf8(generated.to_pem_public_key())
                .map_err(|error| internal().with_source(error))?,
            certificate: None,
        };
        return Ok((AsymmetricKeyAlgorithm::Rsa { bits }, data));
    }
    let algorithm = infer_algorithm_from_private_key_pem(previous_private_key)
        .map_err(|error| internal().with_source(error))?;
    let data = AsymmetricKeyGeneratorImpl
        .generate(&AsymmetricKeySpec {
            algorithm: algorithm.clone(),
        })
        .map_err(|error| internal().with_source(error))?;
    Ok((algorithm, data))
}

fn certificate_domain(certificate: &str) -> Result<String, AppError> {
    let cert = X509::from_pem(certificate.as_bytes()).map_err(AppError::internal)?;
    cert.subject_name()
        .entries_by_nid(Nid::COMMONNAME)
        .next()
        .and_then(|entry| entry.data().to_string().ok())
        .ok_or_else(|| AppError::from_code(CommonErrorCode::InternalError))
}

#[cfg(test)]
mod tests {
    use chrono::Utc;
    use identity_application::key::rotation::KeyRotationMaterialGenerator;
    use identity_domain::key::{
        AsymmetricKeyAlgorithm, AsymmetricKeyData, Key, KeyData, KeyOid, KeyType,
        SymmetricKeyAlgorithm, SymmetricKeyData,
        generator::{AsymmetricKeyGenerator, AsymmetricKeySpec},
    };
    use josekit::{
        jwk::{KeyPair, alg::rsapss::RsaPssKeyPair},
        util::HashAlgorithm,
    };
    use openssl::x509::X509;
    use uuid::Uuid;

    use super::{KeyRotationMaterialGeneratorImpl, generate_same_algorithm};
    use crate::crypto::{
        certificate::generate_self_signed_certificate,
        key::{AsymmetricKeyGeneratorImpl, generate_all_jwks_for_key},
    };

    #[test]
    fn rotation_keeps_curve_and_reissues_certificate_for_new_key() {
        let algorithm = AsymmetricKeyAlgorithm::EcdsaP256;
        let mut previous = AsymmetricKeyGeneratorImpl
            .generate(&AsymmetricKeySpec {
                algorithm: algorithm.clone(),
            })
            .unwrap();
        previous.certificate = Some(
            generate_self_signed_certificate(
                &previous.private_key,
                "https://id.unsvc.net/",
                &algorithm,
            )
            .unwrap(),
        );
        let previous_public = previous.public_key.clone();
        let key = Key {
            oid: KeyOid(Uuid::new_v4()),
            r#type: KeyType::Asymmetric,
            data: KeyData::Asymmetric(previous),
            expires_at: None,
            revoked_at: None,
            created_at: Utc::now(),
            updated_at: None,
        };

        let material = KeyRotationMaterialGeneratorImpl.generate(&key).unwrap();
        let KeyData::Asymmetric(next) = material.data else {
            panic!("asymmetric key expected")
        };
        assert_ne!(next.public_key, previous_public);
        assert_eq!(material.jwks[0].algorithm.as_str(), "ES256");
        let certificate = X509::from_pem(next.certificate.unwrap().as_bytes()).unwrap();
        assert_eq!(
            certificate
                .subject_alt_names()
                .unwrap()
                .get(0)
                .unwrap()
                .dnsname(),
            Some("id.unsvc.net")
        );
    }

    #[test]
    fn rotation_keeps_rsa_pss_signing_algorithm() {
        for (hash, salt_length, expected) in [
            (HashAlgorithm::Sha256, 32, "PS256"),
            (HashAlgorithm::Sha384, 48, "PS384"),
            (HashAlgorithm::Sha512, 64, "PS512"),
        ] {
            let previous = RsaPssKeyPair::generate(2048, hash, hash, salt_length).unwrap();
            let private = String::from_utf8(previous.to_pem_private_key()).unwrap();
            let (algorithm, next) = generate_same_algorithm(&private).unwrap();
            assert_eq!(algorithm, AsymmetricKeyAlgorithm::Rsa { bits: 2048 });
            let jwks = generate_all_jwks_for_key(&next.private_key, "next", None).unwrap();
            assert_eq!(jwks[0].0, expected);
        }
    }

    #[test]
    fn rotation_reissues_certificate_for_rsa_pss() {
        for (hash, salt_length) in [(HashAlgorithm::Sha384, 48), (HashAlgorithm::Sha512, 64)] {
            let previous = RsaPssKeyPair::generate(2048, hash, hash, salt_length).unwrap();
            let private_key = String::from_utf8(previous.to_pem_private_key()).unwrap();
            let certificate = generate_self_signed_certificate(
                &private_key,
                "id.unsvc.net",
                &AsymmetricKeyAlgorithm::Rsa { bits: 2048 },
            )
            .unwrap();
            let key = Key {
                oid: KeyOid(Uuid::new_v4()),
                r#type: KeyType::Asymmetric,
                data: KeyData::Asymmetric(AsymmetricKeyData {
                    private_key,
                    public_key: String::from_utf8(previous.to_pem_public_key()).unwrap(),
                    certificate: Some(certificate),
                }),
                expires_at: None,
                revoked_at: None,
                created_at: Utc::now(),
                updated_at: None,
            };
            let rotated = KeyRotationMaterialGeneratorImpl.generate(&key).unwrap();
            let KeyData::Asymmetric(next) = rotated.data else {
                panic!("asymmetric key expected")
            };
            assert!(next.certificate.is_some());
        }
    }

    #[test]
    fn rotation_replaces_symmetric_material_and_preserves_algorithm() {
        let previous_data = SymmetricKeyData {
            key: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".to_owned(),
            algorithm: SymmetricKeyAlgorithm::XChaCha20Poly1305,
        };
        let key = Key {
            oid: KeyOid(Uuid::new_v4()),
            r#type: KeyType::Symmetric,
            data: KeyData::Symmetric(previous_data.clone()),
            expires_at: None,
            revoked_at: None,
            created_at: Utc::now(),
            updated_at: None,
        };

        let material = KeyRotationMaterialGeneratorImpl.generate(&key).unwrap();
        let KeyData::Symmetric(next) = material.data else {
            panic!("symmetric key expected")
        };
        assert_eq!(next.algorithm, previous_data.algorithm);
        assert_ne!(next.key, previous_data.key);
        assert!(material.jwks.is_empty());
    }
}
