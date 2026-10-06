use super::certificate::generate_self_signed_certificate;
use crate::{
    application::{error::AppError, install::CertificateGenerator},
    domain::key::AsymmetricKeyAlgorithm,
};

pub struct CertificateGeneratorImpl;

impl CertificateGenerator for CertificateGeneratorImpl {
    fn generate_self_signed(
        &self,
        private_key_pem: &str,
        domain: &str,
        algorithm: &AsymmetricKeyAlgorithm,
    ) -> Result<String, AppError> {
        generate_self_signed_certificate(private_key_pem, domain, algorithm)
            .map_err(AppError::internal)
    }
}
