use super::OpenIdProviderService;
use crate::error::{AppError, codes::provider::ProviderErrorCode};
use identity_domain::key::{JwaSigningAlgorithm, JwkAlgorithm, JwsAlgorithm, Key, KeyData};

pub trait SigningAlgorithmDetector: Send + Sync {
    fn detect(&self, key: &Key) -> Vec<JwaSigningAlgorithm>;
}

pub(super) fn detect_id_token_signing_algorithms(
    keys: &[Key],
    detector: &dyn SigningAlgorithmDetector,
) -> Vec<JwsAlgorithm> {
    let mut algos = Vec::new();
    for key in keys {
        if let KeyData::Asymmetric(_) = key.data {
            algos.extend(
                detector
                    .detect(key)
                    .into_iter()
                    .map(JwsAlgorithm::Asymmetric),
            );
        }
    }
    algos.sort_unstable_by_key(|algorithm| algorithm.as_str());
    algos.dedup();
    algos
}

impl OpenIdProviderService {
    pub(super) async fn compute_id_token_signing_algos(
        &self,
    ) -> Result<Vec<JwsAlgorithm>, AppError> {
        let values = match self.key_repo {
            Some(ref key_repo) => {
                let keys = key_repo
                    .list_active_asymmetric()
                    .await
                    .map_err(AppError::map_source(ProviderErrorCode::KeyLookupFailed))?;
                if let Some(key_jwk_repo) = &self.key_jwk_repo {
                    let bindings = key_jwk_repo
                        .list_active()
                        .await
                        .map_err(AppError::map_source(ProviderErrorCode::KeyLookupFailed))?;
                    let mut algorithms = bindings
                        .into_iter()
                        .filter(|binding| keys.iter().any(|key| key.oid == binding.key_oid))
                        .filter_map(|binding| match binding.algorithm {
                            JwkAlgorithm::Signing(algorithm) => {
                                Some(JwsAlgorithm::Asymmetric(algorithm))
                            }
                            JwkAlgorithm::Encryption(_) => None,
                        })
                        .collect::<Vec<_>>();
                    algorithms.sort_unstable_by_key(|algorithm| algorithm.as_str());
                    algorithms.dedup();
                    return Ok(append_conformance_none_alg(algorithms));
                }
                let detected = self
                    .signing_algorithm_detector
                    .as_ref()
                    .map(|detector| detect_id_token_signing_algorithms(&keys, detector.as_ref()))
                    .unwrap_or_default();
                if detected.is_empty() {
                    self.capabilities
                        .id_token_signing_alg_values_supported
                        .clone()
                } else {
                    detected
                }
            }
            None => self
                .capabilities
                .id_token_signing_alg_values_supported
                .clone(),
        };
        Ok(append_conformance_none_alg(values))
    }
}

#[cfg(feature = "allow-none-alg")]
fn append_conformance_none_alg(mut values: Vec<JwsAlgorithm>) -> Vec<JwsAlgorithm> {
    if !values.contains(&JwsAlgorithm::None) {
        values.push(JwsAlgorithm::None);
    }
    values
}

#[cfg(not(feature = "allow-none-alg"))]
fn append_conformance_none_alg(values: Vec<JwsAlgorithm>) -> Vec<JwsAlgorithm> {
    values
}
