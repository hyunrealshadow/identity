use std::{
    sync::Arc,
    time::{Duration, SystemTime},
};

use chrono::Utc;
use identity_domain::{
    auth::{ACR_AAL1, ACR_AAL2},
    key::{JwaSigningAlgorithm, JweContentEncryption, JwkAlgorithm, JwsAlgorithm, Key},
    openid_connect::resource,
};
use josekit::{
    jws::{JwsHeader, JwsSigner},
    jwt,
    jwt::JwtPayload,
};
use serde_json::{from_value, to_string, to_value};
use tracing::Span;
use uuid::Uuid;

use super::client_encryption::select_client_encryption_jwk;
use crate::{
    application::{
        error::{
            AppError,
            codes::{common::CommonErrorCode, openid_connect::OpenIdConnectErrorCode},
        },
        key::asymmetric::AsymmetricKeyService,
        openid_connect::{
            dto::UserInfoClaims,
            jose::{
                asymmetric_signer_from_pem, asymmetric_verifier_from_pem,
                encrypt_compact_with_public_jwk_with_content_type,
            },
            provider::OpenIdProviderService,
        },
    },
    domain::{
        auth::{SessionOid, SessionStatus, repository::SessionRepository},
        authorization::ManagementAuthorityRepository,
        client_authorization::{
            AccessTokenPrincipal, BusinessAuthorizationSnapshotData, ClientAuthorizationData,
            ClientAuthorizationRepository, ClientAuthorizationType, DeviceAuthorizationRepository,
            ManagementAuthorizationSnapshotData,
        },
        key::KeyData,
        openid_connect::{
            ClaimsRequest, OpenIdConnectClientRepository, OpenIdConnectCredentialRepository,
            ScopeSet,
            model::claim::{JwtClaimNames, JwtTokenType, TokenUse},
        },
        rbac::RbacAuthorizationRepository,
        user::{UserOid, repository::UserRepository},
    },
    openid_connect::{
        management::{
            ManagementLivePorts, has_management_claims, validate_management_authorization,
            validate_signed_management_snapshot,
        },
        rbac as shared,
    },
};

pub struct UserInfoService {
    user_repo: Arc<dyn UserRepository>,
    client_repo: Arc<dyn OpenIdConnectClientRepository>,
    credential_repo: Arc<dyn OpenIdConnectCredentialRepository>,
    client_authorization_repo: Arc<dyn ClientAuthorizationRepository>,
    key_service: Arc<AsymmetricKeyService>,
    provider_service: Arc<OpenIdProviderService>,
    /// Device authorizations, so online validation follows the relation a
    /// device issued token belongs to. Optional for services that never see
    /// device tokens.
    device_repo: Option<Arc<dyn DeviceAuthorizationRepository>>,
    /// Live browser sessions for human bearer validation. Optional only for
    /// old unit factories; production must supply it so a token cannot outlive
    /// a revoked, expired or mismatched session.
    session_repo: Option<Arc<dyn SessionRepository>>,
    /// Management ports. Management access tokens fail closed when a required
    /// port is absent; pure self-service tokens do not use them.
    management_authority_repo: Option<Arc<dyn ManagementAuthorityRepository>>,
    /// Live business RBAC state. A business token fails closed when absent.
    rbac_authorization_repo: Option<Arc<dyn RbacAuthorizationRepository>>,
}

/// Explicit principal returned to protocol consumers such as GraphQL. A
/// machine token has `user_oid = None`, a client subject and no session.
#[derive(Debug, Clone)]
pub struct PrincipalClaims {
    pub principal: AccessTokenPrincipal,
    pub user_oid: Option<UserOid>,
    pub client_oid: Uuid,
    pub session_oid: Option<SessionOid>,
    pub scope: ScopeSet,
    pub claims: Option<ClaimsRequest>,
    pub audience: Vec<String>,
    pub auth_time: Option<i64>,
    pub acr: Option<String>,
    pub amr: Vec<String>,
    pub management: Option<ManagementAuthorizationSnapshotData>,
    pub business: Option<BusinessAuthorizationSnapshotData>,
}

pub struct TokenClaims {
    pub user_oid: UserOid,
    pub client_oid: Uuid,
    /// Browser session behind the access token; `None` for device issued
    /// tokens, whose lifecycle follows a device authorization relation.
    pub session_oid: Option<SessionOid>,
    pub scope: ScopeSet,
    pub claims: Option<ClaimsRequest>,
    pub audience: Vec<String>,
    pub auth_time: Option<i64>,
    pub acr: Option<String>,
    pub amr: Vec<String>,
}

impl UserInfoService {
    pub fn new(
        user_repo: Arc<dyn UserRepository>,
        client_repo: Arc<dyn OpenIdConnectClientRepository>,
        credential_repo: Arc<dyn OpenIdConnectCredentialRepository>,
        client_authorization_repo: Arc<dyn ClientAuthorizationRepository>,
        key_service: Arc<AsymmetricKeyService>,
        provider_service: Arc<OpenIdProviderService>,
    ) -> Self {
        Self {
            user_repo,
            client_repo,
            credential_repo,
            client_authorization_repo,
            key_service,
            provider_service,
            device_repo: None,
            session_repo: None,
            management_authority_repo: None,
            rbac_authorization_repo: None,
        }
    }

    /// Attach the device authorization repository, so device issued access
    /// tokens are validated against their relation.
    #[must_use]
    pub fn with_device_repository(
        mut self,
        device_repo: Arc<dyn DeviceAuthorizationRepository>,
    ) -> Self {
        self.device_repo = Some(device_repo);
        self
    }

    #[must_use]
    pub fn with_session_repo(mut self, session_repo: Arc<dyn SessionRepository>) -> Self {
        self.session_repo = Some(session_repo);
        self
    }

    #[must_use]
    pub fn with_management_authority_repository(
        mut self,
        repository: Arc<dyn ManagementAuthorityRepository>,
    ) -> Self {
        self.management_authority_repo = Some(repository);
        self
    }

    #[must_use]
    pub fn with_rbac_authorization_repository(
        mut self,
        repository: Arc<dyn RbacAuthorizationRepository>,
    ) -> Self {
        self.rbac_authorization_repo = Some(repository);
        self
    }

    /// Fails with `invalid_token` when the relation is revoked, expired, or
    /// unknown; a service without a device repository skips the check.
    async fn ensure_device_authorization_active(
        &self,
        device_authorization_oid: Uuid,
    ) -> Result<(), AppError> {
        let Some(device_repo) = &self.device_repo else {
            return Ok(());
        };

        let relation = device_repo
            .find_device_authorization_by_oid(device_authorization_oid)
            .await
            .map_err(AppError::map_source(OpenIdConnectErrorCode::InvalidToken))?;
        let now = Utc::now();
        let active = relation
            .is_some_and(|relation| relation.revoked_at.is_none() && relation.expires_at > now);

        if !active {
            return Err(AppError::from_code(OpenIdConnectErrorCode::InvalidToken));
        }

        Ok(())
    }

    pub async fn get_user_info(
        &self,
        user_oid: UserOid,
        client_oid: Uuid,
        scope: &ScopeSet,
        claims_request: Option<&ClaimsRequest>,
    ) -> Result<UserInfoClaims, AppError> {
        let user = self
            .user_repo
            .find_by_oid(user_oid)
            .await?
            .ok_or_else(|| AppError::from_code(OpenIdConnectErrorCode::UserNotFound))?;

        let issuer = self.provider_service.issuer()?;
        let mut claims = UserInfoClaims::from_user_with_profile_base(&user, issuer.as_str());
        let client = self
            .client_repo
            .find_by_oid(client_oid)
            .await
            .map_err(AppError::map_source(OpenIdConnectErrorCode::InvalidToken))?
            .ok_or_else(|| AppError::from_code(OpenIdConnectErrorCode::InvalidToken))?;
        claims.sub = client.subject_identifier(Uuid::from(user.oid), &issuer);
        claims.apply_scope_filter(scope, claims_request);
        Ok(claims)
    }

    pub async fn sign_user_info(
        &self,
        client_oid: Uuid,
        claims: &UserInfoClaims,
    ) -> Result<Option<String>, AppError> {
        let client = self
            .client_repo
            .find_by_oid(client_oid)
            .await
            .map_err(AppError::map_source(OpenIdConnectErrorCode::InvalidToken))?
            .ok_or_else(|| AppError::from_code(OpenIdConnectErrorCode::InvalidToken))?;

        let Some(algorithms) = client.metadata().userinfo_signed_response_algs.as_deref() else {
            return Ok(None);
        };
        let (alg, key_id, private_key) = self.load_signing_key_for_algs(algorithms).await?;
        let mut header = JwsHeader::new();
        header.set_token_type("JWT");
        header.set_key_id(&key_id);

        let mut payload = user_info_payload(claims)?;
        let issuer = self.provider_service.issuer()?;
        let now = SystemTime::now();
        payload.set_issuer(issuer.as_str());
        payload.set_audience(vec![client.client().oid.to_string()]);
        payload.set_issued_at(&now);

        let signer = build_user_info_signer(&private_key, alg)?;
        let token =
            jwt::encode_with_signer(&payload, &header, &*signer).map_err(AppError::internal)?;

        Ok(Some(token))
    }

    pub async fn encrypt_user_info(
        &self,
        client_oid: Uuid,
        claims: &UserInfoClaims,
        signed_response: Option<&str>,
    ) -> Result<Option<String>, AppError> {
        let client = self
            .client_repo
            .find_by_oid(client_oid)
            .await
            .map_err(AppError::map_source(OpenIdConnectErrorCode::InvalidToken))?
            .ok_or_else(|| AppError::from_code(OpenIdConnectErrorCode::InvalidToken))?;

        let Some(algorithms) = client
            .metadata()
            .userinfo_encrypted_response_algs
            .as_deref()
        else {
            return Ok(None);
        };
        let default_content_encryption = [JweContentEncryption::A128CbcHs256];
        let content_encryptions = client
            .metadata()
            .userinfo_encrypted_response_encs
            .as_deref()
            .unwrap_or(&default_content_encryption);

        let json_body = match signed_response {
            Some(signed) => signed.to_owned(),
            None => to_string(claims).map_err(AppError::internal)?,
        };
        for algorithm in algorithms {
            let Some(public_jwk) = select_client_encryption_jwk(
                &*self.credential_repo,
                client.client().oid,
                algorithm.as_str(),
            )
            .await
            .map_err(AppError::internal)?
            else {
                continue;
            };
            for content_encryption in content_encryptions {
                if let Ok(encrypted) = encrypt_compact_with_public_jwk_with_content_type(
                    json_body.as_bytes(),
                    &public_jwk,
                    algorithm.as_str(),
                    content_encryption.as_str(),
                    signed_response.map(|_| "JWT"),
                ) {
                    return Ok(Some(encrypted));
                }
            }
        }

        Err(AppError::from_code(CommonErrorCode::InternalError))
    }

    /// UserInfo-only validation. Machine tokens never satisfy it: the endpoint
    /// requires a human principal plus `openid`.
    pub async fn validate_access_token(&self, raw_token: &str) -> Result<TokenClaims, AppError> {
        let validated = self.validate_principal_access_token(raw_token).await?;
        if validated.principal != AccessTokenPrincipal::User {
            return Err(AppError::from_code(OpenIdConnectErrorCode::InvalidToken));
        }
        let user_oid = validated
            .user_oid
            .ok_or_else(|| AppError::from_code(OpenIdConnectErrorCode::InvalidToken))?;
        if !validated.scope.openid {
            return Err(AppError::from_code(
                OpenIdConnectErrorCode::InsufficientScope,
            ));
        }
        Ok(TokenClaims {
            user_oid,
            client_oid: validated.client_oid,
            session_oid: validated.session_oid,
            scope: validated.scope,
            claims: validated.claims,
            audience: validated.audience,
            auth_time: validated.auth_time,
            acr: validated.acr,
            amr: validated.amr,
        })
    }

    /// Common principal-aware bearer validation for resource servers such as
    /// GraphQL. Pure self-service tokens keep their previous behavior; a
    /// management token additionally proves its snapshot against live state.
    /// Required management ports are fail-closed.
    #[tracing::instrument(
        skip_all,
        name = "access_token.validate_principal",
        fields(
            principal = tracing::field::Empty,
            management = tracing::field::Empty
        )
    )]
    pub async fn validate_principal_access_token(
        &self,
        raw_token: &str,
    ) -> Result<PrincipalClaims, AppError> {
        let header = jwt::decode_header(raw_token)
            .map_err(AppError::map_source(OpenIdConnectErrorCode::InvalidToken))?;

        let alg = header
            .claim(JwtClaimNames::ALG)
            .and_then(|v| v.as_str())
            .and_then(|value| value.parse::<JwaSigningAlgorithm>().ok())
            .ok_or_else(|| AppError::from_code(OpenIdConnectErrorCode::InvalidToken))?;

        let kid = header
            .claim(JwtClaimNames::KID)
            .and_then(|v| v.as_str())
            .map(|s| s.to_owned());
        let keys = self.key_service.list_available().await?;

        let mut verified_result = None;

        if let Some(kid_str) = kid.as_deref()
            && let Ok(kid_uuid) = Uuid::parse_str(kid_str)
            && let Some(key) = keys.iter().find(|k| Uuid::from(k.oid) == kid_uuid)
            && let Ok(result) = self.verify_jwt_with_key_and_alg(raw_token, key, alg)
        {
            verified_result = Some(result);
        }

        if verified_result.is_none() {
            for key in &keys {
                if let Ok(result) = self.verify_jwt_with_key_and_alg(raw_token, key, alg) {
                    verified_result = Some(result);
                    break;
                }
            }
        }

        let (payload, header) = verified_result
            .ok_or_else(|| AppError::from_code(OpenIdConnectErrorCode::InvalidToken))?;

        let typ = header
            .claim(JwtClaimNames::TYP)
            .and_then(|v| v.as_str())
            .ok_or_else(|| AppError::from_code(OpenIdConnectErrorCode::InvalidToken))?;
        if typ != JwtTokenType::ACCESS_TOKEN && typ != JwtTokenType::ACCESS_TOKEN_FULL {
            return Err(AppError::from_code(OpenIdConnectErrorCode::InvalidToken));
        }

        let expires_at = payload
            .expires_at()
            .ok_or_else(|| AppError::from_code(OpenIdConnectErrorCode::InvalidToken))?;
        if expires_at <= SystemTime::now() {
            return Err(AppError::from_code(OpenIdConnectErrorCode::InvalidToken));
        }
        let issued_at = payload
            .issued_at()
            .ok_or_else(|| AppError::from_code(OpenIdConnectErrorCode::InvalidToken))?;
        if issued_at > SystemTime::now() + Duration::from_secs(60) {
            return Err(AppError::from_code(OpenIdConnectErrorCode::InvalidToken));
        }
        let issuer = self.provider_service.issuer()?;
        if payload.issuer() != Some(issuer.as_str()) {
            return Err(AppError::from_code(OpenIdConnectErrorCode::InvalidToken));
        }
        let audience = payload
            .audience()
            .ok_or_else(|| AppError::from_code(OpenIdConnectErrorCode::InvalidToken))?
            .into_iter()
            .map(str::to_owned)
            .collect::<Vec<_>>();

        let sub = payload
            .claim(JwtClaimNames::SUB)
            .and_then(|v| v.as_str())
            .ok_or_else(|| AppError::from_code(OpenIdConnectErrorCode::InvalidToken))?;

        let token_use = payload
            .claim(JwtClaimNames::TOKEN_USE)
            .and_then(|v| v.as_str())
            .and_then(|value| value.parse::<TokenUse>().ok())
            .ok_or_else(|| AppError::from_code(OpenIdConnectErrorCode::InvalidToken))?;
        if token_use != TokenUse::AccessToken {
            return Err(AppError::from_code(OpenIdConnectErrorCode::InvalidToken));
        }

        let jti = payload
            .jwt_id()
            .ok_or_else(|| AppError::from_code(OpenIdConnectErrorCode::InvalidToken))?;
        let access_token_oid = Uuid::parse_str(jti)
            .map_err(|_| AppError::from_code(OpenIdConnectErrorCode::InvalidToken))?;
        let access_token_record = self
            .client_authorization_repo
            .find_by_oid(access_token_oid)
            .await
            .map_err(AppError::map_source(OpenIdConnectErrorCode::InvalidToken))?
            .ok_or_else(|| AppError::from_code(OpenIdConnectErrorCode::InvalidToken))?;
        if access_token_record.type_ != ClientAuthorizationType::AccessToken
            || access_token_record.revoked_at.is_some()
            || access_token_record.expires_at <= Utc::now()
        {
            return Err(AppError::from_code(OpenIdConnectErrorCode::InvalidToken));
        }
        let ClientAuthorizationData::AccessToken(access_token_data) = &access_token_record.data
        else {
            return Err(AppError::from_code(OpenIdConnectErrorCode::InvalidToken));
        };

        let principal = access_token_data.principal;
        let user_oid = match principal {
            AccessTokenPrincipal::User => {
                let user = Uuid::parse_str(sub)
                    .map_err(|_| AppError::from_code(OpenIdConnectErrorCode::InvalidToken))?;
                if access_token_data.user_oid.as_deref() != Some(sub) {
                    return Err(AppError::from_code(OpenIdConnectErrorCode::InvalidToken));
                }
                Some(UserOid(user))
            }
            AccessTokenPrincipal::Client => {
                let subject = Uuid::parse_str(sub)
                    .map_err(|_| AppError::from_code(OpenIdConnectErrorCode::InvalidToken))?;
                if subject != access_token_record.client_oid
                    || access_token_data.user_oid.is_some()
                    || access_token_data.session_oid.is_some()
                    || access_token_data.protected_session_id.is_some()
                    || access_token_data.device_authorization_oid.is_some()
                {
                    return Err(AppError::from_code(OpenIdConnectErrorCode::InvalidToken));
                }
                None
            }
        };
        Span::current().record("principal", principal.as_str());

        // A signed principal claim is mandatory for new tokens but legacy
        // tokens without it remain human tokens by serde default.
        if let Some(signed_principal) = payload
            .claim(JwtClaimNames::PRINCIPAL_KIND)
            .and_then(|value| value.as_str())
            && signed_principal != principal.as_str()
        {
            return Err(AppError::from_code(OpenIdConnectErrorCode::InvalidToken));
        }

        // Live client state applies to every token, not only management ones.
        let live_client = self
            .client_repo
            .find_by_oid(access_token_record.client_oid)
            .await
            .map_err(AppError::map_source(OpenIdConnectErrorCode::InvalidToken))?
            .ok_or_else(|| AppError::from_code(OpenIdConnectErrorCode::InvalidToken))?;

        let mut session_has_aal2 = None;
        let device_linked = access_token_data.device_authorization_oid.is_some();
        if let Some(user_oid) = user_oid {
            // Disabled and locked users cannot keep using a human token.
            let user = self
                .user_repo
                .find_by_oid(user_oid)
                .await
                .map_err(AppError::map_source(OpenIdConnectErrorCode::InvalidToken))?
                .ok_or_else(|| AppError::from_code(OpenIdConnectErrorCode::InvalidToken))?;
            if !user.enabled || user.locked {
                return Err(AppError::from_code(OpenIdConnectErrorCode::InvalidToken)
                    .with_param("reason", "user is disabled or locked"));
            }

            match access_token_data.session_oid {
                Some(session_oid) => {
                    if let Some(session_repo) = &self.session_repo {
                        let session = session_repo
                            .find_by_oid(session_oid)
                            .await
                            .map_err(AppError::map_source(OpenIdConnectErrorCode::InvalidToken))?
                            .ok_or_else(|| {
                                AppError::from_code(OpenIdConnectErrorCode::InvalidToken)
                            })?;
                        let now = Utc::now();
                        let active = session.revoked_at.is_none()
                            && session.status == SessionStatus::ACTIVE
                            && session.expires_at.is_none_or(|expiry| expiry > now)
                            && session.user_oid.to_string() == sub;
                        if !active {
                            return Err(AppError::from_code(OpenIdConnectErrorCode::InvalidToken)
                                .with_param("reason", "session is not active for the user"));
                        }
                        session_has_aal2 = Some(session.effective_acr(now) == Some(ACR_AAL2));
                    }
                }
                None if !device_linked => {
                    return Err(AppError::from_code(OpenIdConnectErrorCode::InvalidToken)
                        .with_param("reason", "human token requires a live session"));
                }
                None => {}
            }
        }

        if let Some(device_authorization_oid) = access_token_data
            .device_authorization_oid
            .as_deref()
            .and_then(|oid| Uuid::parse_str(oid).ok())
        {
            self.ensure_device_authorization_active(device_authorization_oid)
                .await?;
        }
        let client_id = payload
            .claim(JwtClaimNames::CLIENT_ID)
            .and_then(|value| value.as_str())
            .ok_or_else(|| AppError::from_code(OpenIdConnectErrorCode::InvalidToken))?;
        if client_id != access_token_record.client_oid.to_string() {
            return Err(AppError::from_code(OpenIdConnectErrorCode::InvalidToken));
        }

        let scope_str = payload
            .claim(JwtClaimNames::SCOPE)
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let scope = ScopeSet::parse(scope_str)
            .map_err(|_| AppError::from_code(OpenIdConnectErrorCode::InvalidToken))?;
        if scope.to_scope_string() != access_token_data.scope {
            return Err(AppError::from_code(OpenIdConnectErrorCode::InvalidToken));
        }

        let resource_audience = audience
            .iter()
            .filter(|uri| resource::valid_resource_uri(uri))
            .cloned()
            .collect::<Vec<_>>();
        if scope.has_resource_permissions() && !resource_audience.is_empty() {
            let selection = self
                .provider_service
                .select_resources(
                    &resource_audience,
                    &resource_audience,
                    &access_token_data.scope,
                )
                .await
                .map_err(AppError::map_source(OpenIdConnectErrorCode::InvalidToken))?;
            if ScopeSet::parse(&selection.scope).ok().as_ref() != Some(&scope) {
                return Err(AppError::from_code(OpenIdConnectErrorCode::InvalidToken));
            }
        }
        let persisted_issuance = access_token_data.management.as_ref();
        let persisted_management = shared::management_snapshot(persisted_issuance);
        let persisted_business = shared::business_snapshot(persisted_issuance);
        let machine_management =
            principal == AccessTokenPrincipal::Client && scope.has_management_scopes();
        if machine_management && persisted_business.is_none() {
            return Err(AppError::from_code(OpenIdConnectErrorCode::InvalidToken));
        }
        let management = persisted_management.is_some()
            || (principal == AccessTokenPrincipal::User && scope.has_management_scopes());
        if management {
            let persisted = persisted_management
                .ok_or_else(|| AppError::from_code(OpenIdConnectErrorCode::InvalidToken))?;
            validate_signed_management_snapshot(persisted, &payload)?;
            validate_management_authorization(
                ManagementLivePorts {
                    binding_repo: self.management_authority_repo.as_ref(),
                    provider_service: &self.provider_service,
                },
                &live_client,
                persisted,
                &access_token_data.scope,
                &scope,
                principal,
            )
            .await?;
        } else if has_management_claims(&payload) {
            // Signed management claims without a persisted management snapshot
            // are a tampering signal.
            return Err(AppError::from_code(OpenIdConnectErrorCode::InvalidToken));
        }

        let resource_is_rbac = if resource_audience.is_empty() {
            false
        } else {
            self.provider_service
                .has_rbac_resource(&resource_audience)
                .await
                .map_err(AppError::map_source(OpenIdConnectErrorCode::InvalidToken))?
        };
        if let Some(persisted) = persisted_business {
            shared::validate_signed_business_snapshot(persisted, &payload)?;
            shared::validate_business_authorization(
                shared::BusinessLivePorts {
                    repository: self.rbac_authorization_repo.as_ref(),
                    provider_service: &self.provider_service,
                },
                shared::BusinessTokenAuthorization {
                    live_client: &live_client,
                    persisted,
                    persisted_scope: &access_token_data.scope,
                    scope: &scope,
                    principal,
                    subject_user_oid: user_oid,
                    audience: &audience,
                },
            )
            .await?;
        } else if shared::has_business_claims(&payload) {
            // Signed business claims without a persisted snapshot are a
            // tampering signal.
            return Err(AppError::from_code(OpenIdConnectErrorCode::InvalidToken));
        } else if resource_is_rbac {
            // A token for a resource that now uses RBAC must carry a business
            // snapshot. This invalidates legacy tokens across a policy switch.
            return Err(AppError::from_code(OpenIdConnectErrorCode::InvalidToken));
        }
        Span::current().record("management", management);

        let claims = payload
            .claim("claims")
            .cloned()
            .map(from_value)
            .transpose()
            .map_err(|_| AppError::from_code(OpenIdConnectErrorCode::InvalidToken))?;

        let auth_time = payload
            .claim(JwtClaimNames::AUTH_TIME)
            .and_then(|value| value.as_i64());
        let mut acr = payload
            .claim(JwtClaimNames::ACR)
            .and_then(|value| value.as_str())
            .map(str::to_owned);
        if acr.as_deref() == Some(ACR_AAL2)
            && (session_has_aal2 == Some(false)
                || !auth_time
                    .is_some_and(|time| (0..=3600).contains(&(Utc::now().timestamp() - time))))
        {
            acr = Some(ACR_AAL1.to_owned());
        }
        let amr = payload
            .claim(JwtClaimNames::AMR)
            .cloned()
            .map(from_value)
            .transpose()
            .map_err(|_| AppError::from_code(OpenIdConnectErrorCode::InvalidToken))?
            .unwrap_or_default();

        Ok(PrincipalClaims {
            principal,
            user_oid,
            client_oid: access_token_record.client_oid,
            session_oid: access_token_data.session_oid,
            scope,
            claims,
            audience,
            auth_time,
            acr,
            amr,
            management: persisted_management.cloned(),
            business: persisted_business.cloned(),
        })
    }

    fn verify_jwt_with_key_and_alg(
        &self,
        token: &str,
        key: &Key,
        alg: JwaSigningAlgorithm,
    ) -> Result<(jwt::JwtPayload, JwsHeader), AppError> {
        let public_key = match &key.data {
            KeyData::Asymmetric(data) => data.public_key.as_bytes(),
            _ => return Err(AppError::from_code(CommonErrorCode::InternalError)),
        };

        let verifier = asymmetric_verifier_from_pem(alg.as_str(), public_key)
            .map_err(|_| AppError::from_code(OpenIdConnectErrorCode::InvalidToken))?;
        let (payload, header) = jwt::decode_with_verifier(token, verifier.as_ref())
            .map_err(|_| AppError::from_code(OpenIdConnectErrorCode::InvalidToken))?;

        Ok((payload, header))
    }

    async fn load_signing_key_for_algs(
        &self,
        algorithms: &[JwsAlgorithm],
    ) -> Result<(JwaSigningAlgorithm, String, String), AppError> {
        let keys = self.key_service.list_available().await?;
        let bindings = self.key_service.list_available_jwks().await?;

        for requested in algorithms {
            let JwsAlgorithm::Asymmetric(alg) = requested else {
                continue;
            };
            for binding in bindings
                .iter()
                .filter(|binding| binding.algorithm == JwkAlgorithm::Signing(*alg))
            {
                let Some(key) = keys.iter().find(|key| key.oid == binding.key_oid) else {
                    continue;
                };
                let KeyData::Asymmetric(data) = &key.data else {
                    continue;
                };
                let key_id = binding
                    .jwk
                    .key_id()
                    .map(str::to_owned)
                    .unwrap_or_else(|| Uuid::from(binding.oid).to_string());
                return Ok((*alg, key_id, data.private_key.clone()));
            }
        }

        Err(AppError::from_code(CommonErrorCode::InternalError))
    }
}

fn user_info_payload(claims: &UserInfoClaims) -> Result<jwt::JwtPayload, AppError> {
    let value = to_value(claims).map_err(AppError::internal)?;
    let object = value
        .as_object()
        .ok_or_else(|| AppError::from_code(CommonErrorCode::InternalError))?;
    let mut payload = JwtPayload::new();
    for (name, value) in object {
        payload
            .set_claim(name, Some(value.clone()))
            .map_err(AppError::internal)?;
    }
    Ok(payload)
}

fn build_user_info_signer(
    private_key_pem: &str,
    alg: JwaSigningAlgorithm,
) -> Result<Box<dyn JwsSigner>, AppError> {
    asymmetric_signer_from_pem(alg.as_str(), private_key_pem.as_bytes()).map_err(AppError::internal)
}

#[cfg(test)]
mod tests {
    use identity_domain::client_authorization::ManagementGrantKindData;
    use josekit::{jwt, jwt::JwtPayload};
    use serde_json::json;
    use uuid::Uuid;

    use crate::openid_connect::management::{
        has_management_claims, signed_management_snapshot, validate_signed_management_snapshot,
    };

    use super::JwtClaimNames;

    const GRANT_VERSION: &str = "22222222-2222-2222-2222-222222222222";
    const POLICY_VERSION: &str = "33333333-3333-3333-3333-333333333333";
    const CLIENT_POLICY_VERSION: &str = "44444444-4444-4444-4444-444444444444";

    fn management_payload() -> jwt::JwtPayload {
        let mut payload = JwtPayload::new();
        payload
            .set_claim(
                JwtClaimNames::MANAGEMENT_GRANT_KIND,
                Some(json!("user_rbac")),
            )
            .unwrap();
        payload
            .set_claim(
                JwtClaimNames::MANAGEMENT_GRANT_OID,
                Some(json!("11111111-1111-1111-1111-111111111111")),
            )
            .unwrap();
        payload
            .set_claim(
                JwtClaimNames::MANAGEMENT_GRANT_VERSION,
                Some(json!(GRANT_VERSION)),
            )
            .unwrap();
        payload
            .set_claim(
                JwtClaimNames::MANAGEMENT_POLICY_VERSION,
                Some(json!(POLICY_VERSION)),
            )
            .unwrap();
        payload
            .set_claim(
                JwtClaimNames::MANAGEMENT_CLIENT_POLICY_VERSION,
                Some(json!(CLIENT_POLICY_VERSION)),
            )
            .unwrap();
        payload
            .set_claim(JwtClaimNames::MANAGEMENT_ROLE, Some(json!(null)))
            .unwrap();
        payload
            .set_claim(
                JwtClaimNames::MANAGEMENT_PERMISSIONS,
                Some(json!(["management.user.read"])),
            )
            .unwrap();
        payload
    }

    #[test]
    fn absolute_management_claims_round_trip_through_the_validator_parser() {
        let payload = management_payload();
        let snapshot = signed_management_snapshot(&payload).unwrap().unwrap();
        assert_eq!(snapshot.grant_kind, ManagementGrantKindData::UserRbac);
        assert_eq!(
            snapshot.grant_version,
            Uuid::parse_str(GRANT_VERSION).unwrap()
        );
        assert_eq!(
            snapshot.policy_version,
            Uuid::parse_str(POLICY_VERSION).unwrap()
        );
        assert_eq!(
            snapshot.client_policy_version,
            Uuid::parse_str(CLIENT_POLICY_VERSION).unwrap()
        );
        assert_eq!(
            snapshot.permissions,
            vec!["management.user.read".to_owned()]
        );
        assert!(has_management_claims(&payload));
    }

    #[test]
    fn signed_snapshot_must_match_oid_version_and_client_policy() {
        let persisted = signed_management_snapshot(&management_payload())
            .unwrap()
            .unwrap();
        validate_signed_management_snapshot(&persisted, &management_payload()).unwrap();

        let mut changed_oid = management_payload();
        changed_oid
            .set_claim(
                JwtClaimNames::MANAGEMENT_GRANT_OID,
                Some(json!("22222222-2222-2222-2222-222222222222")),
            )
            .unwrap();
        assert!(validate_signed_management_snapshot(&persisted, &changed_oid).is_err());

        let mut changed_version = management_payload();
        changed_version
            .set_claim(
                JwtClaimNames::MANAGEMENT_GRANT_VERSION,
                Some(json!("55555555-5555-5555-5555-555555555555")),
            )
            .unwrap();
        assert!(validate_signed_management_snapshot(&persisted, &changed_version).is_err());

        let mut changed_client_policy = management_payload();
        changed_client_policy
            .set_claim(
                JwtClaimNames::MANAGEMENT_CLIENT_POLICY_VERSION,
                Some(json!("66666666-6666-6666-6666-666666666666")),
            )
            .unwrap();
        assert!(validate_signed_management_snapshot(&persisted, &changed_client_policy).is_err());
    }

    #[test]
    fn partial_management_claims_fail_closed() {
        // JwtPayload has no remove; a new payload with one claim is enough.
        let mut partial = JwtPayload::new();
        partial
            .set_claim(
                JwtClaimNames::MANAGEMENT_GRANT_KIND,
                Some(json!("administrator_binding")),
            )
            .unwrap();
        assert!(signed_management_snapshot(&partial).is_err());
        assert!(
            signed_management_snapshot(&JwtPayload::new())
                .unwrap()
                .is_none()
        );
    }
}
