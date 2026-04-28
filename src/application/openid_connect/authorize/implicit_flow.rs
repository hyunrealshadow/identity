use super::*;
use std::fmt::Write;
use uuid::Uuid;

impl AuthorizeService {
    pub(super) async fn approve_implicit_flow(
        &self,
        request: &AuthorizationRequestData,
        session_oid: Uuid,
        user_oid: Uuid,
        response_type: ResponseType,
        auth_time: Option<i64>,
    ) -> Result<url::Url, AppError> {
        let nonce = request
            .nonce
            .as_deref()
            .ok_or_else(|| AppError::from_code(AuthorizeErrorCode::ImplicitNonceRequired))?;

        let redirect_uri = url::Url::parse(&request.redirect_uri).map_err(|error| {
            AppError::from_code(AuthorizeErrorCode::StoredRedirectUriInvalid).with_source(error)
        })?;

        let client_id = Uuid::parse_str(&request.client_id).map_err(|error| {
            AppError::from_code(AuthorizeErrorCode::StoredClientIdInvalid).with_source(error)
        })?;

        let user_oid_obj = UserOid(user_oid);
        let user = self
            .user_repo
            .find_by_oid(user_oid_obj)
            .await
            .map_err(|error| {
                AppError::from_code(AuthorizeErrorCode::ClientLookupFailed).with_source(error)
            })?
            .ok_or_else(|| AppError::from_code(AuthorizeErrorCode::ClientNotFound))?;

        let issuer = self.provider_service.issuer()?;
        let (signing_key_id, signing_key_pem, signing_alg) = self.load_signing_key_impl().await?;
        let audience = client_id.to_string();
        let auth_time_val = auth_time.unwrap_or_else(|| chrono::Utc::now().timestamp());
        let scope = ScopeSet::parse(&request.scope).map_err(|error| {
            AppError::from_code(AuthorizeErrorCode::ScopeInvalid).with_source(error)
        })?;
        let claims = request
            .claims
            .as_ref()
            .and_then(|claims| serde_json::from_str::<serde_json::Value>(claims).ok());

        let include_access_token = matches!(response_type, ResponseType::TokenIdToken);

        let (access_token, expires_in) = if include_access_token {
            let access_token_record = self
                .client_authorization_repo
                .create(
                    client_id,
                    ClientAuthorizationType::AccessToken,
                    serde_json::to_value(crate::domain::client_authorization::AccessTokenData {
                        scope: request.scope.clone(),
                        user_oid: user_oid.to_string(),
                        session_oid: session_oid.to_string(),
                        authorization_code_oid: None,
                    })
                    .map_err(|error| {
                        AppError::from_code(AuthorizeErrorCode::SerializeCodeFailed)
                            .with_source(error)
                    })?,
                    chrono::Utc::now() + chrono::Duration::hours(1),
                )
                .await
                .map_err(|error| {
                    AppError::from_code(AuthorizeErrorCode::StoreCodeFailed).with_source(error)
                })?;
            let at = self.sign_implicit_access_token(
                &signing_key_id,
                &signing_key_pem,
                &signing_alg,
                &issuer,
                &audience,
                &audience,
                &user_oid.to_string(),
                &session_oid.to_string(),
                &request.scope,
                &access_token_record.oid.to_string(),
                claims.as_ref(),
            )?;
            (Some(at), 3600u64)
        } else {
            (None, 0)
        };

        let id_token = self.sign_implicit_id_token(
            &signing_key_id,
            &signing_key_pem,
            &signing_alg,
            &issuer,
            &audience,
            &user,
            nonce,
            auth_time_val,
            request
                .acr_values
                .as_ref()
                .and_then(|v| v.first().map(String::as_str)),
            access_token.as_deref(),
            &scope,
            claims.as_ref(),
        )?;

        let mut fragment = format!("id_token={id_token}");
        if let Some(ref at) = access_token {
            write!(fragment, "&access_token={at}").unwrap();
            write!(fragment, "&token_type=Bearer").unwrap();
            write!(fragment, "&expires_in={expires_in}").unwrap();
            write!(fragment, "&scope={}", urlencoding(&request.scope)).unwrap();
        }
        write!(fragment, "&state={}", urlencoding(&request.state)).unwrap();

        let mut url = redirect_uri;
        url.set_fragment(Some(&fragment));

        Ok(url)
    }
}

fn urlencoding(s: &str) -> String {
    let mut result = String::new();
    for &b in s.as_bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                result.push(b as char);
            }
            b' ' => result.push_str("%20"),
            _ => {
                use std::fmt::Write;
                write!(result, "%{:02X}", b).unwrap();
            }
        }
    }
    result
}
