use crate::{
    application::openid_connect::provider::SigningAlgorithmDetector,
    domain::key::{JwaSigningAlgorithm, Key, KeyData},
};

use super::key::{infer_algorithm_from_private_key_pem, jwa_algorithm_can_sign};

pub struct SigningAlgorithmDetectorImpl;

impl SigningAlgorithmDetector for SigningAlgorithmDetectorImpl {
    fn detect(&self, key: &Key) -> Vec<JwaSigningAlgorithm> {
        let KeyData::Asymmetric(data) = &key.data else {
            return vec![];
        };

        let Ok(algorithm) = infer_algorithm_from_private_key_pem(&data.private_key) else {
            return vec![];
        };

        let pem = data.private_key.as_bytes();
        JwaSigningAlgorithm::trials_for_key_type(&algorithm)
            .iter()
            .copied()
            .filter(|jwa| jwa_algorithm_can_sign(*jwa, pem))
            .collect()
    }
}
