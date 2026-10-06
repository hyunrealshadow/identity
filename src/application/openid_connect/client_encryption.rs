use identity_domain::{
    client::model::ClientOid,
    key::PublicJwk,
    openid_connect::{
        OpenIdConnectCredentialData, OpenIdConnectCredentialRepository,
        OpenIdConnectCredentialRepositoryError, OpenIdConnectCredentialType,
    },
};

pub(super) async fn select_client_encryption_jwk(
    repository: &dyn OpenIdConnectCredentialRepository,
    client_oid: ClientOid,
    algorithm: &str,
) -> Result<Option<PublicJwk>, OpenIdConnectCredentialRepositoryError> {
    let mut candidates = Vec::new();
    for credential_type in [
        OpenIdConnectCredentialType::ClientPublicKey,
        OpenIdConnectCredentialType::ClientJsonWebKeySet,
    ] {
        for credential in repository
            .find_active_by_client_oid_and_type(client_oid, credential_type)
            .await?
        {
            match credential.data {
                OpenIdConnectCredentialData::ClientPublicKey { jwk: Some(jwk), .. } => {
                    candidates.push(jwk);
                }
                OpenIdConnectCredentialData::ClientJsonWebKeySet { jwks, .. } => {
                    candidates.extend(jwks);
                }
                _ => {}
            }
        }
    }

    Ok(candidates
        .iter()
        .find(|jwk| jwk.algorithm() == Some(algorithm) && supports_encryption(jwk, algorithm))
        .or_else(|| {
            candidates
                .iter()
                .find(|jwk| jwk.algorithm().is_none() && supports_encryption(jwk, algorithm))
        })
        .cloned())
}

fn supports_encryption(jwk: &PublicJwk, algorithm: &str) -> bool {
    let key_use = match jwk {
        PublicJwk::Rsa { key_use, .. }
        | PublicJwk::Ec { key_use, .. }
        | PublicJwk::Okp { key_use, .. } => key_use.as_deref(),
    };
    if key_use.is_some_and(|value| value != "enc") {
        return false;
    }
    match jwk {
        PublicJwk::Rsa { .. } => matches!(algorithm, "RSA-OAEP" | "RSA-OAEP-256"),
        PublicJwk::Ec { .. } | PublicJwk::Okp { .. } => {
            matches!(algorithm, "ECDH-ES" | "ECDH-ES+A128KW" | "ECDH-ES+A256KW")
        }
    }
}

#[cfg(test)]
mod tests {
    use chrono::{Duration, Utc};
    use identity_domain::openid_connect::OpenIdConnectCredential;
    use serde_json::{from_value, json};
    use uuid::Uuid;

    use crate::openid_connect::tests::fixtures::mocks::MockOpenIdConnectCredentialRepository;

    use super::*;

    #[tokio::test]
    async fn selects_matching_algorithm_from_a_client_jwks() {
        let jwks = from_value::<Vec<PublicJwk>>(json!([
            {"kty":"RSA","use":"enc","alg":"RSA-OAEP","kid":"rsa","n":"AQAB","e":"AQAB"},
            {"kty":"EC","use":"enc","alg":"ECDH-ES","kid":"ec","crv":"P-256","x":"AQAB","y":"AQAB"}
        ]))
        .unwrap();
        let client_oid = Uuid::new_v4();
        let credential = OpenIdConnectCredential {
            oid: Uuid::new_v4(),
            client_oid,
            r#type: OpenIdConnectCredentialType::ClientJsonWebKeySet,
            hint: "jwks".to_owned(),
            data: OpenIdConnectCredentialData::ClientJsonWebKeySet {
                jwks_uri: "https://client.example/jwks".parse().unwrap(),
                last_updated: Utc::now(),
                expires_at: Utc::now() + Duration::hours(1),
                public_keys: Vec::new(),
                jwks,
            },
            expires_at: Utc::now() + Duration::hours(1),
            revoked_at: None,
            created_at: Utc::now(),
            updated_at: None,
        };
        let mut repository = MockOpenIdConnectCredentialRepository::new();
        repository
            .expect_find_active_by_client_oid_and_type()
            .returning(move |_, credential_type| {
                Ok(
                    if credential_type == OpenIdConnectCredentialType::ClientJsonWebKeySet {
                        vec![credential.clone()]
                    } else {
                        Vec::new()
                    },
                )
            });

        let selected = select_client_encryption_jwk(&repository, client_oid, "ECDH-ES")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(selected.key_id(), Some("ec"));
        assert!(
            select_client_encryption_jwk(&repository, client_oid, "RSA-OAEP-256")
                .await
                .unwrap()
                .is_none()
        );
    }
}
