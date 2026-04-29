use crate::{
    application::{
        error::{AppError, codes::key::KeyErrorCode},
        key::asymmetric::{GeneratedKeyJwk, KeyJwkGenerator},
    },
    infrastructure::crypto::key::generate_all_jwks_for_key,
};

pub struct KeyJwkGeneratorImpl;

impl KeyJwkGenerator for KeyJwkGeneratorImpl {
    fn generate(
        &self,
        private_key_pem: &str,
        key_id: &str,
        certificate_pem: Option<&str>,
    ) -> Result<Vec<GeneratedKeyJwk>, AppError> {
        generate_all_jwks_for_key(private_key_pem, key_id, certificate_pem)
            .map_err(|error| {
                AppError::from_code(KeyErrorCode::JwkGenerationFailed).with_source(error)
            })?
            .into_iter()
            .map(|(algorithm, jwk)| {
                let jwk = serde_json::to_value(jwk).map_err(|error| {
                    AppError::from_code(KeyErrorCode::JwkSerializationFailed).with_source(error)
                })?;
                Ok(GeneratedKeyJwk { algorithm, jwk })
            })
            .collect()
    }
}
