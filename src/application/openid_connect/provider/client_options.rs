//! Values a client may register, derived from the provider's live keys.
//!
//! Discovery, the management options query and client metadata validation all
//! read these lists, so an administrator can choose only what this instance
//! can honour now. Signing the provider performs follows its active signing
//! keys; request objects can be encrypted only to its active encryption keys.
//! Algorithms that use the client's own keys follow the static capabilities.

use identity_domain::key::{JwaEncryptionAlgorithm, JwkAlgorithm, JwsAlgorithm};

use super::{OpenIdProviderCapabilities, OpenIdProviderService};
use crate::error::{AppError, codes::provider::ProviderErrorCode};

/// Supported values for client registration metadata, as JOSE names.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ClientMetadataOptions {
    pub subject_types: Vec<String>,
    pub acr_values: Vec<String>,
    pub id_token_signing_algs: Vec<String>,
    pub id_token_encryption_algs: Vec<String>,
    pub id_token_encryption_encs: Vec<String>,
    pub userinfo_signing_algs: Vec<String>,
    pub userinfo_encryption_algs: Vec<String>,
    pub userinfo_encryption_encs: Vec<String>,
    pub request_object_signing_algs: Vec<String>,
    pub request_object_encryption_algs: Vec<String>,
    pub request_object_encryption_encs: Vec<String>,
    pub token_endpoint_auth_signing_algs: Vec<String>,
}

fn names<T: ToString>(values: &[T]) -> Vec<String> {
    values.iter().map(ToString::to_string).collect()
}

impl ClientMetadataOptions {
    /// The static capabilities, before live keys narrow them.
    #[must_use]
    pub fn from_capabilities(capabilities: &OpenIdProviderCapabilities) -> Self {
        Self {
            subject_types: names(&capabilities.subject_types_supported),
            acr_values: capabilities.acr_values_supported.clone(),
            id_token_signing_algs: names(&capabilities.id_token_signing_alg_values_supported),
            id_token_encryption_algs: names(&capabilities.id_token_encryption_alg_values_supported),
            id_token_encryption_encs: names(&capabilities.id_token_encryption_enc_values_supported),
            userinfo_signing_algs: names(&capabilities.id_token_signing_alg_values_supported),
            userinfo_encryption_algs: names(&capabilities.userinfo_encryption_alg_values_supported),
            userinfo_encryption_encs: names(&capabilities.userinfo_encryption_enc_values_supported),
            request_object_signing_algs: names(
                &capabilities.request_object_signing_alg_values_supported,
            ),
            request_object_encryption_algs: names(
                &capabilities.request_object_encryption_alg_values_supported,
            ),
            request_object_encryption_encs: names(
                &capabilities.request_object_encryption_enc_values_supported,
            ),
            token_endpoint_auth_signing_algs: capabilities
                .token_endpoint_auth_signing_alg_values_supported
                .iter()
                .filter(|algorithm| **algorithm != JwsAlgorithm::None)
                .map(ToString::to_string)
                .collect(),
        }
    }
}

impl OpenIdProviderService {
    /// Request object encryption algorithms backed by an active encryption key.
    /// Without key storage (tests and tooling) the static capabilities apply.
    pub(super) async fn compute_request_object_encryption_algos(
        &self,
    ) -> Result<Vec<JwaEncryptionAlgorithm>, AppError> {
        let supported = &self
            .capabilities
            .request_object_encryption_alg_values_supported;
        let (Some(key_repo), Some(key_jwk_repo)) = (&self.key_repo, &self.key_jwk_repo) else {
            return Ok(supported.clone());
        };
        let keys = key_repo
            .list_active_asymmetric()
            .await
            .map_err(AppError::map_source(ProviderErrorCode::KeyLookupFailed))?;
        let bindings = key_jwk_repo
            .list_active()
            .await
            .map_err(AppError::map_source(ProviderErrorCode::KeyLookupFailed))?;
        let available = bindings
            .into_iter()
            .filter(|binding| keys.iter().any(|key| key.oid == binding.key_oid))
            .filter_map(|binding| match binding.algorithm {
                JwkAlgorithm::Encryption(algorithm) => Some(algorithm),
                JwkAlgorithm::Signing(_) => None,
            })
            .collect::<Vec<_>>();
        // Keep the capability order, which is also the published order.
        Ok(supported
            .iter()
            .copied()
            .filter(|algorithm| available.contains(algorithm))
            .collect())
    }

    /// The live supported values. Content encryption for request objects is
    /// offered only while some key management algorithm is.
    pub async fn client_metadata_options(&self) -> Result<ClientMetadataOptions, AppError> {
        let signing = names(&self.compute_id_token_signing_algos().await?);
        let request_object_encryption_algs =
            names(&self.compute_request_object_encryption_algos().await?);
        let mut options = ClientMetadataOptions::from_capabilities(&self.capabilities);
        options.id_token_signing_algs = signing.clone();
        options.userinfo_signing_algs = signing;
        if request_object_encryption_algs.is_empty() {
            options.request_object_encryption_encs.clear();
        }
        options.request_object_encryption_algs = request_object_encryption_algs;
        Ok(options)
    }
}
