//! Which algorithms a client's registered credentials can serve right now.
//!
//! Console settings let an administrator pick encryption and signature
//! algorithms that only work with a matching client key. This reports, for a
//! set of candidate algorithms, the ones the runtime would actually find a key
//! for, using the same selection and verifier construction as issuance and
//! verification, so the two cannot disagree.

use std::sync::Arc;

use identity_domain::{
    client::model::ClientOid,
    key::PublicJwk,
    openid_connect::{
        OpenIdConnectCredentialData, OpenIdConnectCredentialRepository, OpenIdConnectCredentialType,
    },
};

use super::{
    client_encryption::select_client_encryption_jwk,
    jose::{asymmetric_verifier_from_pem, asymmetric_verifier_from_public_jwk},
};
use crate::error::{AppError, codes::client};

/// What the client's active credentials cover.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ClientKeyCoverage {
    /// Candidates the client has a public encryption key for (ID Token and
    /// UserInfo encryption).
    pub encryption_algs: Vec<String>,
    /// Candidates a stored client public key can verify (request objects and
    /// `private_key_jwt` assertions).
    pub verification_algs: Vec<String>,
    /// Whether a JWKS URI is registered. Assertion verification fetches it
    /// live, so stored keys are not the whole picture for assertions.
    pub remote_keys: bool,
    /// Whether an active client secret can verify HMAC-signed
    /// (`client_secret_jwt`) assertions.
    pub secret: bool,
}

pub struct ClientKeyCoverageService {
    credentials: Arc<dyn OpenIdConnectCredentialRepository>,
}

impl ClientKeyCoverageService {
    #[must_use]
    pub fn new(credentials: Arc<dyn OpenIdConnectCredentialRepository>) -> Self {
        Self { credentials }
    }

    #[tracing::instrument(skip_all, name = "client.key_coverage")]
    pub async fn coverage(
        &self,
        client_oid: ClientOid,
        encryption_candidates: &[String],
        signature_candidates: &[String],
    ) -> Result<ClientKeyCoverage, AppError> {
        let mut encryption_algs = Vec::new();
        for algorithm in encryption_candidates {
            if select_client_encryption_jwk(&*self.credentials, client_oid, algorithm)
                .await
                .map_err(client::error::StorageFailed::map_source())?
                .is_some()
            {
                encryption_algs.push(algorithm.clone());
            }
        }

        let mut jwks = Vec::<PublicJwk>::new();
        let mut pems = Vec::<String>::new();
        let mut remote_keys = false;
        for credential_type in [
            OpenIdConnectCredentialType::ClientPublicKey,
            OpenIdConnectCredentialType::ClientJsonWebKeySet,
        ] {
            for credential in self
                .credentials
                .find_active_by_client_oid_and_type(client_oid, credential_type)
                .await
                .map_err(client::error::StorageFailed::map_source())?
            {
                match credential.data {
                    OpenIdConnectCredentialData::ClientPublicKey { public_key, jwk } => {
                        jwks.extend(jwk);
                        pems.push(public_key);
                    }
                    OpenIdConnectCredentialData::ClientJsonWebKeySet {
                        public_keys,
                        jwks: set,
                        ..
                    } => {
                        remote_keys = true;
                        jwks.extend(set);
                        pems.extend(public_keys);
                    }
                    OpenIdConnectCredentialData::ClientSecret { .. } => {}
                }
            }
        }
        let verification_algs = signature_candidates
            .iter()
            .filter(|algorithm| {
                jwks.iter()
                    .any(|jwk| asymmetric_verifier_from_public_jwk(algorithm, jwk).is_ok())
                    || pems
                        .iter()
                        .any(|pem| asymmetric_verifier_from_pem(algorithm, pem.as_bytes()).is_ok())
            })
            .cloned()
            .collect();

        let secret = !self
            .credentials
            .find_active_by_client_oid_and_type(
                client_oid,
                OpenIdConnectCredentialType::ClientSecret,
            )
            .await
            .map_err(client::error::StorageFailed::map_source())?
            .is_empty();

        Ok(ClientKeyCoverage {
            encryption_algs,
            verification_algs,
            remote_keys,
            secret,
        })
    }
}

#[cfg(test)]
mod tests {
    use chrono::{Duration, Utc};
    use identity_domain::openid_connect::OpenIdConnectCredential;
    use serde_json::{from_value, json};
    use uuid::Uuid;

    use super::*;
    use crate::openid_connect::tests::fixtures::mocks::MockOpenIdConnectCredentialRepository;

    /// Public half of a throwaway 2048-bit RSA key.
    const RSA_N: &str = "vBjiW0-QXbvgyg5yOgmf_yWPBPC-348GDpLSjaVN1tN_3kHeKLBEM1Rjl1yPKuC8iSEHKrbC9IBLJhY9jeWUAovguH_Fk3V9jnwg3ksFVxkkpcYiTYL1gOUrTGctwysrywkze2rwUaAONdQf7eElpUTga7RUC1cM5K6I5bXrDlEdwnBhq32cn5wxRgv5fohwhjEC7hGcmnuMMsMA9y5NMOTkjEoq1HwdAXlOpEeBdCfvuUvgeFPeMpvNz1y71AjnL5sqyh9Xri93FcnGFjjZtk1Oq1SncFBrPKzQQC26zKavpp7KZY9KlhMm6QQO73TYr6qAn1Ncj_laFPoilLaW4w";

    fn credential(
        client_oid: Uuid,
        r#type: OpenIdConnectCredentialType,
        data: OpenIdConnectCredentialData,
    ) -> OpenIdConnectCredential {
        OpenIdConnectCredential {
            oid: Uuid::new_v4(),
            client_oid,
            r#type,
            hint: "test".to_owned(),
            data,
            expires_at: Utc::now() + Duration::hours(1),
            revoked_at: None,
            created_at: Utc::now(),
            updated_at: None,
        }
    }

    fn service(credentials: Vec<OpenIdConnectCredential>) -> ClientKeyCoverageService {
        let mut repository = MockOpenIdConnectCredentialRepository::new();
        repository
            .expect_find_active_by_client_oid_and_type()
            .returning(move |_, credential_type| {
                Ok(credentials
                    .iter()
                    .filter(|credential| credential.r#type == credential_type)
                    .cloned()
                    .collect())
            });
        ClientKeyCoverageService::new(Arc::new(repository))
    }

    fn names(values: &[&str]) -> Vec<String> {
        values.iter().map(|value| (*value).to_owned()).collect()
    }

    #[tokio::test]
    async fn an_rsa_jwks_covers_what_the_runtime_would_use_it_for() {
        let client_oid = Uuid::new_v4();
        let jwks = from_value::<Vec<PublicJwk>>(json!([
            {"kty":"RSA","use":"enc","alg":"RSA-OAEP","kid":"enc","n":RSA_N,"e":"AQAB"},
            {"kty":"RSA","use":"sig","kid":"sig","n":RSA_N,"e":"AQAB"}
        ]))
        .unwrap();
        let coverage = service(vec![credential(
            client_oid,
            OpenIdConnectCredentialType::ClientJsonWebKeySet,
            OpenIdConnectCredentialData::ClientJsonWebKeySet {
                jwks_uri: "https://client.example/jwks".parse().unwrap(),
                last_updated: Utc::now(),
                expires_at: Utc::now() + Duration::hours(1),
                public_keys: Vec::new(),
                jwks,
            },
        )])
        .coverage(
            client_oid,
            &names(&["RSA-OAEP", "RSA-OAEP-256", "ECDH-ES"]),
            &names(&["RS256", "PS256", "ES256", "HS256"]),
        )
        .await
        .unwrap();

        assert_eq!(coverage.encryption_algs, ["RSA-OAEP"]);
        assert_eq!(coverage.verification_algs, ["RS256", "PS256"]);
        assert!(coverage.remote_keys);
        assert!(!coverage.secret);
    }

    #[tokio::test]
    async fn a_client_with_only_a_secret_covers_no_key_algorithm() {
        let client_oid = Uuid::new_v4();
        let coverage = service(vec![credential(
            client_oid,
            OpenIdConnectCredentialType::ClientSecret,
            OpenIdConnectCredentialData::ClientSecret {
                secret: "secret".to_owned(),
            },
        )])
        .coverage(
            client_oid,
            &names(&["RSA-OAEP"]),
            &names(&["RS256", "HS256"]),
        )
        .await
        .unwrap();

        assert_eq!(
            coverage,
            ClientKeyCoverage {
                secret: true,
                ..Default::default()
            }
        );
    }
}
