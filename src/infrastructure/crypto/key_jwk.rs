use josekit::jwk::Jwk;
use serde_json::{from_value, to_value};

use crate::{
    application::{
        error::{AppError, codes::key},
        key::asymmetric::{GeneratedKeyJwk, KeyJwkGenerator},
    },
    domain::key::generator::KeyMaterialError,
    domain::key::{JwaSigningAlgorithm, PublicJwk},
    infrastructure::crypto::key::{generate_all_jwks_for_key, generate_jwks_for_key},
};

pub struct KeyJwkGeneratorImpl;

fn bindings(
    generated: Result<Vec<(String, Jwk)>, KeyMaterialError>,
) -> Result<Vec<GeneratedKeyJwk>, AppError> {
    generated
        .map_err(key::error::JwkGenerationFailed::map_source())?
        .into_iter()
        .map(|(algorithm, jwk)| {
            let jwk_value =
                to_value(jwk).map_err(key::error::JwkSerializationFailed::map_source())?;
            let jwk = from_value::<PublicJwk>(jwk_value)
                .map_err(key::error::JwkSerializationFailed::map_source())?;
            let algorithm = algorithm
                .parse()
                .map_err(|_| key::error::UnsupportedAlgorithm::new(&algorithm).into_error())?;
            Ok(GeneratedKeyJwk { algorithm, jwk })
        })
        .collect()
}

impl KeyJwkGenerator for KeyJwkGeneratorImpl {
    fn generate(
        &self,
        private_key_pem: &str,
        key_id: &str,
        certificate_pem: Option<&str>,
    ) -> Result<Vec<GeneratedKeyJwk>, AppError> {
        bindings(generate_all_jwks_for_key(
            private_key_pem,
            key_id,
            certificate_pem,
        ))
    }

    fn generate_for(
        &self,
        private_key_pem: &str,
        key_id: &str,
        certificate_pem: Option<&str>,
        signing: &[JwaSigningAlgorithm],
    ) -> Result<Vec<GeneratedKeyJwk>, AppError> {
        bindings(generate_jwks_for_key(
            private_key_pem,
            key_id,
            certificate_pem,
            signing,
        ))
    }
}
