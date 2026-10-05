use super::*;
use crate::openid_connect::dto::scoped_standard_claims;
use crate::openid_connect::jose::{asymmetric_signer_from_pem, front_channel_hash};
use identity_domain::key::{JwaSigningAlgorithm, JwsAlgorithm};
use identity_domain::openid_connect::OpenIdConnectClient;
use identity_domain::openid_connect::{ClaimsRequest, ScopeSet};
use identity_domain::user::User;
use josekit::jws::JwsSigner;
use std::time::Duration;
use std::time::SystemTime;
use tokio::task::spawn_blocking;
use url::Url;

pub(super) struct SignAccessTokenInput<'a> {
    pub resources: &'a [String],
    pub token_id: &'a str,
    pub key_id: &'a str,
    pub private_key_pem: &'a str,
    pub alg: JwaSigningAlgorithm,
    pub issuer: &'a Url,
    pub audience: &'a str,
    pub client_id: &'a str,
    pub user_oid: &'a Uuid,
    pub client: &'a OpenIdConnectClient,
    pub user: Option<&'a User>,
    /// `None` for device issued tokens: they have no browser session, so no
    /// `sid` claim is emitted (a forged one would be a lie).
    pub protected_session_id: Option<&'a str>,
    pub scope: &'a str,
    pub claims: Option<&'a ClaimsRequest>,
    pub auth_time: Option<i64>,
    pub acr: Option<&'a str>,
    pub amr: &'a [String],
}

pub(super) struct SignIdTokenInput<'a> {
    pub key_id: &'a str,
    pub private_key_pem: &'a str,
    pub alg: JwsAlgorithm,
    pub issuer: &'a Url,
    pub audience: &'a str,
    pub client: &'a OpenIdConnectClient,
    pub user: &'a User,
    /// Granted scope for the issued token; consulted only when the client
    /// opts in to scoped standard claims in the ID Token.
    pub scope: &'a str,
    pub nonce: Option<&'a str>,
    pub auth_time: Option<i64>,
    pub acr: Option<&'a str>,
    pub amr: &'a [String],
    pub access_token: Option<&'a str>,
    pub protected_session_id: Option<&'a str>,
}

impl TokenService {
    pub(super) async fn sign_access_token(
        &self,
        input: SignAccessTokenInput<'_>,
    ) -> Result<String, AppError> {
        let mut header = JwsHeader::new();
        header.set_token_type(JwtTokenType::ACCESS_TOKEN);
        header.set_key_id(input.key_id);

        let mut payload = JwtPayload::new();
        let now = SystemTime::now();
        payload.set_issuer(input.issuer.as_str());
        payload.set_subject(input.user_oid.to_string());
        payload.set_audience(if input.resources.is_empty() {
            vec![input.audience]
        } else {
            input.resources.iter().map(String::as_str).collect()
        });
        payload.set_issued_at(&now);
        payload.set_expires_at(&(now + Duration::from_secs(3600)));
        payload.set_jwt_id(input.token_id);
        payload
            .set_claim(
                JwtClaimNames::CLIENT_ID,
                Some(serde_json::json!(input.client_id)),
            )
            .map_err(AppError::map_source(TokenErrorCode::SignAccessTokenFailed))?;
        payload
            .set_claim(JwtClaimNames::SCOPE, Some(serde_json::json!(input.scope)))
            .map_err(AppError::map_source(TokenErrorCode::SignAccessTokenFailed))?;
        if let Some(protected_session_id) = input.protected_session_id {
            payload
                .set_claim(
                    JwtClaimNames::SID,
                    Some(serde_json::json!(protected_session_id)),
                )
                .map_err(AppError::map_source(TokenErrorCode::SignAccessTokenFailed))?;
        }
        payload
            .set_claim(
                JwtClaimNames::TOKEN_USE,
                Some(serde_json::json!(TokenUse::AccessToken)),
            )
            .map_err(AppError::map_source(TokenErrorCode::SignAccessTokenFailed))?;
        if let Some(auth_time) = input.auth_time {
            payload
                .set_claim(JwtClaimNames::AUTH_TIME, Some(serde_json::json!(auth_time)))
                .map_err(AppError::map_source(TokenErrorCode::SignAccessTokenFailed))?;
        }
        if let Some(acr) = input.acr {
            payload
                .set_claim(JwtClaimNames::ACR, Some(serde_json::json!(acr)))
                .map_err(AppError::map_source(TokenErrorCode::SignAccessTokenFailed))?;
        }
        payload
            .set_claim(JwtClaimNames::AMR, Some(serde_json::json!(input.amr)))
            .map_err(AppError::map_source(TokenErrorCode::SignAccessTokenFailed))?;
        if let Some(claims_value) = input.claims {
            payload
                .set_claim(
                    "claims",
                    Some(
                        serde_json::to_value(claims_value)
                            .map_err(AppError::map_source(TokenErrorCode::SignAccessTokenFailed))?,
                    ),
                )
                .map_err(AppError::map_source(TokenErrorCode::SignAccessTokenFailed))?;
        }
        if input
            .client
            .metadata()
            .settings
            .include_scoped_claims_in_access_token
            && let Some(user) = input.user
        {
            let scope = ScopeSet::parse(input.scope)
                .map_err(AppError::map_source(TokenErrorCode::SignAccessTokenFailed))?;
            for (name, value) in scoped_standard_claims(user, &scope, None, input.issuer.as_str()) {
                payload
                    .set_claim(&name, Some(value))
                    .map_err(AppError::map_source(TokenErrorCode::SignAccessTokenFailed))?;
            }
        }

        let private_key_pem = input.private_key_pem.to_owned();
        let alg = input.alg;
        spawn_blocking(move || {
            let signer = build_access_token_signer(&private_key_pem, alg)?;
            jwt::encode_with_signer(&payload, &header, &*signer)
                .map_err(AppError::map_source(TokenErrorCode::SignAccessTokenFailed))
        })
        .await
        .map_err(AppError::internal)?
    }

    pub(super) async fn sign_id_token(
        &self,
        input: SignIdTokenInput<'_>,
    ) -> Result<String, AppError> {
        if input.client.metadata().require_auth_time == Some(true) && input.auth_time.is_none() {
            return Err(AppError::from_code(TokenErrorCode::SignIdTokenFailed));
        }
        let mut header = JwsHeader::new();
        header.set_token_type("JWT");
        header.set_key_id(input.key_id);

        let mut payload = JwtPayload::new();
        let now = SystemTime::now();
        payload.set_issuer(input.issuer.as_str());
        payload.set_subject(
            input
                .client
                .subject_identifier(Uuid::from(input.user.oid), input.issuer),
        );
        payload.set_audience(vec![input.audience]);
        payload.set_issued_at(&now);
        payload.set_expires_at(&(now + Duration::from_secs(3600)));
        payload
            .set_claim(
                JwtClaimNames::AZP,
                Some(serde_json::json!(input.client.client().oid.to_string())),
            )
            .map_err(AppError::map_source(TokenErrorCode::SignIdTokenFailed))?;
        payload
            .set_claim(JwtClaimNames::AMR, Some(serde_json::json!(input.amr)))
            .map_err(AppError::map_source(TokenErrorCode::SignIdTokenFailed))?;
        if let Some(nonce) = input.nonce {
            payload
                .set_claim(JwtClaimNames::NONCE, Some(serde_json::json!(nonce)))
                .map_err(AppError::map_source(TokenErrorCode::SignIdTokenFailed))?;
        }
        if let Some(auth_time) = input.auth_time {
            payload
                .set_claim(JwtClaimNames::AUTH_TIME, Some(serde_json::json!(auth_time)))
                .map_err(AppError::map_source(TokenErrorCode::SignIdTokenFailed))?;
        }
        if let Some(acr) = input.acr {
            payload
                .set_claim(JwtClaimNames::ACR, Some(serde_json::json!(acr)))
                .map_err(AppError::map_source(TokenErrorCode::SignIdTokenFailed))?;
        }
        if input.alg != JwsAlgorithm::None
            && let Some(access_token) = input.access_token
        {
            let at_hash = front_channel_hash(access_token, input.alg.as_str())
                .map_err(AppError::map_source(TokenErrorCode::SignIdTokenFailed))?;
            payload
                .set_claim(JwtClaimNames::AT_HASH, Some(serde_json::json!(at_hash)))
                .map_err(AppError::map_source(TokenErrorCode::SignIdTokenFailed))?;
        }
        if let Some(protected_session_id) = input.protected_session_id {
            payload
                .set_claim(
                    JwtClaimNames::SID,
                    Some(serde_json::json!(protected_session_id)),
                )
                .map_err(AppError::map_source(TokenErrorCode::SignIdTokenFailed))?;
        }

        if input
            .client
            .metadata()
            .settings
            .include_scoped_claims_in_id_token
        {
            let scope = ScopeSet::parse(input.scope)
                .map_err(AppError::map_source(TokenErrorCode::SignIdTokenFailed))?;
            let standard_claims =
                scoped_standard_claims(input.user, &scope, None, input.issuer.as_str());
            for (name, value) in standard_claims {
                payload
                    .set_claim(&name, Some(value))
                    .map_err(AppError::map_source(TokenErrorCode::SignIdTokenFailed))?;
            }
        }

        if input.alg == JwsAlgorithm::None {
            #[cfg(feature = "allow-none-alg")]
            return Self::sign_unsigned_id_token(&header, &payload);

            #[cfg(not(feature = "allow-none-alg"))]
            return Err(AppError::from_code(TokenErrorCode::SignIdTokenFailed));
        }

        let private_key_pem = input.private_key_pem.to_owned();
        let alg = input.alg;
        spawn_blocking(move || {
            let signer = build_id_token_signer(&private_key_pem, alg)?;
            jwt::encode_with_signer(&payload, &header, &*signer)
                .map_err(AppError::map_source(TokenErrorCode::SignIdTokenFailed))
        })
        .await
        .map_err(AppError::internal)?
    }

    #[cfg(feature = "allow-none-alg")]
    fn sign_unsigned_id_token(
        header: &JwsHeader,
        payload: &JwtPayload,
    ) -> Result<String, AppError> {
        jwt::encode_unsecured(payload, header)
            .map_err(AppError::map_source(TokenErrorCode::SignIdTokenFailed))
    }
}

fn build_access_token_signer(
    private_key_pem: &str,
    alg: JwaSigningAlgorithm,
) -> Result<Box<dyn JwsSigner>, AppError> {
    build_jws_signer(
        private_key_pem,
        alg.as_str(),
        TokenErrorCode::SignAccessTokenFailed,
    )
}

fn build_id_token_signer(
    private_key_pem: &str,
    alg: JwsAlgorithm,
) -> Result<Box<dyn JwsSigner>, AppError> {
    let JwsAlgorithm::Asymmetric(alg) = alg else {
        return Err(AppError::from_code(TokenErrorCode::SignIdTokenFailed));
    };
    build_jws_signer(
        private_key_pem,
        alg.as_str(),
        TokenErrorCode::SignIdTokenFailed,
    )
}

fn build_jws_signer(
    private_key_pem: &str,
    alg: &str,
    error_code: TokenErrorCode,
) -> Result<Box<dyn JwsSigner>, AppError> {
    asymmetric_signer_from_pem(alg, private_key_pem.as_bytes())
        .map_err(|error| AppError::from_code(error_code).with_source(error))
}
