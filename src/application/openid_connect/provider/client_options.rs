//! Values a client may register in its advanced settings.
//!
//! These are the provider's static capabilities, independent of which keys
//! are active now. An algorithm list is an order of preference: each issuance
//! uses the first listed algorithm the provider currently has a key for, so
//! rotating keys never invalidates stored client settings. Discovery still
//! publishes only what the active keys can honour.

use identity_domain::{
    auth::AuthenticationContextClass,
    key::{JwaEncryptionAlgorithm, JwkAlgorithm, JwsAlgorithm},
};

use super::{
    OpenIdProviderCapabilities, OpenIdProviderService,
    capabilities::supported_asymmetric_jws_algorithms, signing::append_conformance_none_alg,
};
use crate::error::{AppError, codes::provider};

/// Supported values for client registration metadata, as JOSE names.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ClientMetadataOptions {
    pub subject_types: Vec<String>,
    pub acr_values: Vec<AuthenticationContextClass>,
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

/// Algorithms with an active provider key, as JOSE names.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ActiveKeyAlgorithms {
    pub signing: Vec<String>,
    pub request_object_encryption: Vec<String>,
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
            .map_err(provider::error::KeyLookupFailed::map_source())?;
        let bindings = key_jwk_repo
            .list_active()
            .await
            .map_err(provider::error::KeyLookupFailed::map_source())?;
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

    /// Algorithms the provider holds an active key for right now: provider
    /// signing (ID Token, UserInfo) and request object decryption. Keys may
    /// be revoked at any time, so this only informs the administrator; client
    /// settings are never validated against it.
    pub async fn active_key_algorithms(&self) -> Result<ActiveKeyAlgorithms, AppError> {
        Ok(ActiveKeyAlgorithms {
            signing: names(&self.compute_id_token_signing_algos().await?),
            request_object_encryption: names(
                &self.compute_request_object_encryption_algos().await?,
            ),
        })
    }

    /// Values a client may choose in its advanced settings: everything the
    /// provider can sign or decrypt with given a key, not narrowed by the
    /// active keys. The static discovery fallback (`ES256` alone) is not the
    /// supported set, so provider signing lists every asymmetric algorithm.
    #[must_use]
    pub fn client_metadata_options(&self) -> ClientMetadataOptions {
        let signing = names(&append_conformance_none_alg(
            supported_asymmetric_jws_algorithms(),
        ));
        let mut options = ClientMetadataOptions::from_capabilities(&self.capabilities);
        options.id_token_signing_algs = signing.clone();
        options.userinfo_signing_algs = signing;
        options
    }
}
