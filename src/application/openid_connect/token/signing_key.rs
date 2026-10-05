use super::*;
use crate::openid_connect::jose::asymmetric_signer_from_pem;
use identity_domain::key::{JwaSigningAlgorithm, JwsAlgorithm};

impl TokenService {
    pub(super) async fn load_configured_signing_key(
        &self,
        requested: Option<&[JwsAlgorithm]>,
    ) -> Result<(String, String, JwsAlgorithm), AppError> {
        let Some(requested) = requested else {
            return self.load_configured_signing_key_single(None).await;
        };
        for algorithm in requested {
            match self
                .load_configured_signing_key_single(Some(*algorithm))
                .await
            {
                Ok(key) => return Ok(key),
                Err(error)
                    if error.code()
                        == AppError::from_code(TokenErrorCode::NoSigningKeyAvailable).code() => {}
                Err(error) => return Err(error),
            }
        }
        Err(AppError::from_code(TokenErrorCode::NoSigningKeyAvailable))
    }

    async fn load_configured_signing_key_single(
        &self,
        requested: Option<JwsAlgorithm>,
    ) -> Result<(String, String, JwsAlgorithm), AppError> {
        match requested {
            Some(JwsAlgorithm::Asymmetric(alg)) => {
                if let Some(provider) = &self.runtime_key_ring {
                    let ring = provider.current_value();
                    if let Some(key) = ring.signing_key().filter(|key| key.algorithm == alg) {
                        return Ok((
                            key.key_id.clone(),
                            key.private_key_pem.clone(),
                            JwsAlgorithm::Asymmetric(alg),
                        ));
                    }
                }

                let keys = self
                    .key_repo
                    .list_active_asymmetric()
                    .await
                    .map_err(AppError::map_source(TokenErrorCode::KeyListFailed))?;
                for key in keys {
                    let KeyData::Asymmetric(data) = &key.data else {
                        continue;
                    };
                    if asymmetric_signer_from_pem(alg.as_str(), data.private_key.as_bytes())
                        .is_err()
                    {
                        continue;
                    }
                    if let Some(binding) = self
                        .key_jwk_repo
                        .find_active_by_key_oid_and_algorithm(key.oid, alg)
                        .await
                        .map_err(AppError::map_source(TokenErrorCode::KeyListFailed))?
                    {
                        return Ok((
                            Uuid::from(binding.oid).to_string(),
                            data.private_key.clone(),
                            JwsAlgorithm::Asymmetric(alg),
                        ));
                    }
                }
                Err(AppError::from_code(TokenErrorCode::NoSigningKeyAvailable))
            }
            Some(JwsAlgorithm::None) if cfg!(feature = "allow-none-alg") => {
                Ok((String::new(), String::new(), JwsAlgorithm::None))
            }
            Some(_) => Err(AppError::from_code(TokenErrorCode::NoSigningKeyAvailable)),
            None => {
                let (key_id, private_key, alg) = self.load_signing_key().await?;
                Ok((key_id, private_key, JwsAlgorithm::Asymmetric(alg)))
            }
        }
    }

    pub(super) async fn load_signing_key(
        &self,
    ) -> Result<(String, String, JwaSigningAlgorithm), AppError> {
        if let Some(provider) = &self.runtime_key_ring {
            let ring = provider.current_value();
            let key = ring
                .signing_key()
                .ok_or_else(|| AppError::from_code(TokenErrorCode::NoSigningKeyAvailable))?;
            return Ok((
                key.key_id.clone(),
                key.private_key_pem.clone(),
                key.algorithm,
            ));
        }

        let keys = self
            .key_repo
            .list_active_asymmetric()
            .await
            .map_err(AppError::map_source(TokenErrorCode::KeyListFailed))?;

        for key in keys {
            if let KeyData::Asymmetric(data) = &key.data {
                let Some(alg) = self
                    .signing_algorithm_detector
                    .detect(&key)
                    .into_iter()
                    .next()
                else {
                    continue;
                };

                let Some(binding) = self
                    .key_jwk_repo
                    .find_active_by_key_oid_and_algorithm(key.oid, alg)
                    .await
                    .map_err(AppError::map_source(TokenErrorCode::KeyListFailed))?
                else {
                    continue;
                };

                return Ok((
                    Uuid::from(binding.oid).to_string(),
                    data.private_key.clone(),
                    alg,
                ));
            }
        }

        Err(AppError::from_code(TokenErrorCode::NoSigningKeyAvailable))
    }

    pub(super) async fn load_access_token_signing_key(
        &self,
        configured_signing_key: &(String, String, JwsAlgorithm),
    ) -> Result<(String, String, JwaSigningAlgorithm), AppError> {
        if let (key_id, private_key, JwsAlgorithm::Asymmetric(alg)) = configured_signing_key {
            return Ok((key_id.clone(), private_key.clone(), *alg));
        }

        // `none` applies only to ID tokens; access tokens still need a signing key.
        self.load_signing_key().await
    }
}
