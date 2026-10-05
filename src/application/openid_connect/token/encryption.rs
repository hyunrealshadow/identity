use super::*;
use crate::openid_connect::client_encryption::select_client_encryption_jwk;
use crate::openid_connect::jose::encrypt_compact_with_public_jwk_with_content_type;
use identity_domain::openid_connect::OpenIdConnectClient;

impl TokenService {
    pub(super) async fn encrypt_token_for_client(
        &self,
        signed_jwt: &str,
        client: &OpenIdConnectClient,
    ) -> Result<String, AppError> {
        let Some(algorithms) = client
            .metadata()
            .id_token_encrypted_response_algs
            .as_deref()
        else {
            return Ok(signed_jwt.to_owned());
        };
        let default_content_encryption = [JweContentEncryption::A128CbcHs256];
        let content_encryptions = client
            .metadata()
            .id_token_encrypted_response_encs
            .as_deref()
            .unwrap_or(&default_content_encryption);
        let mut found_key = false;
        for algorithm in algorithms {
            let Some(public_jwk) = select_client_encryption_jwk(
                &*self.credential_repo,
                client.client().oid,
                algorithm.as_str(),
            )
            .await
            .map_err(AppError::map_source(TokenErrorCode::EncryptionKeyNotFound))?
            else {
                continue;
            };
            found_key = true;
            for content_encryption in content_encryptions {
                if let Ok(encrypted) = encrypt_compact_with_public_jwk_with_content_type(
                    signed_jwt.as_bytes(),
                    &public_jwk,
                    algorithm.as_str(),
                    content_encryption.as_str(),
                    Some("JWT"),
                ) {
                    return Ok(encrypted);
                }
            }
        }
        Err(AppError::from_code(if found_key {
            TokenErrorCode::EncryptionFailed
        } else {
            TokenErrorCode::EncryptionKeyNotFound
        }))
    }
}
