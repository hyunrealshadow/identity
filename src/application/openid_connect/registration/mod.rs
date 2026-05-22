use std::sync::Arc;

use chrono::{Duration, Utc};
use url::Url;
use uuid::Uuid;

use crate::{
    application::{
        error::{AppError, codes::registration::RegistrationErrorCode},
        setting::runtime::SettingProvider,
    },
    domain::{
        client::model::{Client, ClientProtocol},
        openid_connect::{
            OpenIdConnectClientMetadata, OpenIdConnectClientPlatform,
            OpenIdConnectClientRegistration, OpenIdConnectClientRegistrationRepository,
            OpenIdConnectClientSettings, SubjectType,
        },
        setting::DynamicClientRegistrationSetting,
    },
};

mod credential;
mod request;
mod response;
#[cfg(test)]
mod tests;
mod token;
mod validation;

pub use request::{DynamicClientJwks, DynamicClientRegistrationRequest};
pub use response::DynamicClientRegistrationResponse;

use credential::{client_credentials_from_jwks, client_credentials_from_jwks_uri};
use response::{registration_client_uri, response_from_client};
use token::{default_skip_consent, generate_client_secret, generate_registration_access_token};
use validation::{
    parse_application_type, reject_none_outside_conformance, split_scope,
    validate_initiate_login_uri, validate_sector_identifier_uri,
};

pub struct DynamicClientRegistrationService {
    enabled: Arc<dyn SettingProvider<DynamicClientRegistrationSetting>>,
    repo: Arc<dyn OpenIdConnectClientRegistrationRepository>,
}

impl DynamicClientRegistrationService {
    #[must_use]
    pub fn new(
        enabled: Arc<dyn SettingProvider<DynamicClientRegistrationSetting>>,
        repo: Arc<dyn OpenIdConnectClientRegistrationRepository>,
    ) -> Self {
        Self { enabled, repo }
    }

    pub async fn register(
        &self,
        request: DynamicClientRegistrationRequest,
        issuer: &Url,
    ) -> Result<DynamicClientRegistrationResponse, AppError> {
        if !*self.enabled.current_value() {
            return Err(AppError::from_code(
                RegistrationErrorCode::DynamicRegistrationDisabled,
            ));
        }
        if request.redirect_uris.is_empty() {
            return Err(AppError::from_code(
                RegistrationErrorCode::RedirectUrisRequired,
            ));
        }
        if request
            .redirect_uris
            .iter()
            .any(|uri| uri.fragment().is_some())
        {
            return Err(AppError::from_code(
                RegistrationErrorCode::InvalidRedirectUri,
            ));
        }

        let platform = parse_application_type(request.application_type.as_deref())?;
        let subject_type = request
            .subject_type
            .as_deref()
            .map(str::parse::<SubjectType>)
            .transpose()
            .map_err(|error| {
                AppError::from_code(RegistrationErrorCode::UnsupportedSubjectType)
                    .with_param(
                        "subject_type",
                        request.subject_type.as_deref().unwrap_or_default(),
                    )
                    .with_source(error)
            })?;
        validate_sector_identifier_uri(
            request.sector_identifier_uri.as_ref(),
            &request.redirect_uris,
        )
        .await?;
        validate_initiate_login_uri(request.initiate_login_uri.as_ref())?;
        let token_auth_method = request
            .token_endpoint_auth_method
            .clone()
            .unwrap_or_else(|| "client_secret_basic".to_owned());
        reject_none_outside_conformance(
            "token_endpoint_auth_method",
            Some(token_auth_method.as_str()),
        )?;
        reject_none_outside_conformance(
            "id_token_signed_response_alg",
            request.id_token_signed_response_alg.as_deref(),
        )?;
        let public_client = token_auth_method == "none";
        let client_secret = (!public_client).then(generate_client_secret);
        let client_secret_expires_at = client_secret
            .as_ref()
            .map(|_| (Utc::now() + Duration::days(365)).timestamp());
        let registration_access_token = generate_registration_access_token();
        let assigned_scopes = split_scope(request.scope.as_deref());
        let client_name = request
            .client_name
            .clone()
            .unwrap_or_else(|| "Dynamic OpenID Connect Client".to_owned());
        let mut credentials = client_credentials_from_jwks(request.jwks.as_ref())?;
        if let Some(credential) =
            client_credentials_from_jwks_uri(request.jwks_uri.as_ref()).await?
        {
            credentials.push(credential);
        }

        let metadata = OpenIdConnectClientMetadata {
            post_logout_redirect_uris: request.post_logout_redirect_uris.clone(),
            frontchannel_logout_uri: request.frontchannel_logout_uri.clone(),
            frontchannel_logout_session_required: request.frontchannel_logout_session_required,
            backchannel_logout_uri: request.backchannel_logout_uri.clone(),
            backchannel_logout_session_required: request.backchannel_logout_session_required,
            response_types: request.response_types.clone(),
            grant_types: request.grant_types.clone(),
            contacts: request.contacts.clone(),
            logo_uri: request.logo_uri.clone(),
            client_uri: request.client_uri.clone(),
            policy_uri: request.policy_uri.clone(),
            tos_uri: request.tos_uri.clone(),
            sector_identifier_uri: request.sector_identifier_uri.clone(),
            subject_type,
            id_token_signed_response_alg: request.id_token_signed_response_alg.clone(),
            id_token_encrypted_response_alg: request.id_token_encrypted_response_alg.clone(),
            id_token_encrypted_response_enc: request.id_token_encrypted_response_enc.clone(),
            userinfo_signed_response_alg: request.userinfo_signed_response_alg.clone(),
            userinfo_encrypted_response_alg: request.userinfo_encrypted_response_alg.clone(),
            userinfo_encrypted_response_enc: request.userinfo_encrypted_response_enc.clone(),
            request_object_signing_alg: request.request_object_signing_alg.clone(),
            request_object_encryption_alg: request.request_object_encryption_alg.clone(),
            request_object_encryption_enc: request.request_object_encryption_enc.clone(),
            token_endpoint_auth_method: Some(token_auth_method.clone()),
            token_endpoint_auth_signing_alg: request.token_endpoint_auth_signing_alg.clone(),
            default_max_age: request.default_max_age,
            require_auth_time: request.require_auth_time,
            default_acr_values: request.default_acr_values.clone(),
            initiate_login_uri: request.initiate_login_uri.clone(),
            request_uris: request.request_uris.clone(),
            settings: OpenIdConnectClientSettings {
                skip_consent: default_skip_consent(),
                allow_public_client_flow: public_client,
            },
        };

        let client = Client {
            oid: Uuid::new_v4(),
            protocol: ClientProtocol::OpenIdConnect,
            name: client_name,
            names: vec![],
            description: None,
            created_at: Utc::now(),
            updated_at: None,
        };
        let application_type = platform.to_string();
        let registration = OpenIdConnectClientRegistration {
            client,
            metadata,
            platforms: vec![OpenIdConnectClientPlatform {
                platform,
                redirect_uris: request.redirect_uris.clone(),
            }],
            assigned_scopes: assigned_scopes.clone(),
            client_secret: client_secret.clone(),
            credentials,
            registration_access_token: registration_access_token.clone(),
        };
        let client_id = self.repo.create(registration).await.map_err(|error| {
            AppError::from_code(RegistrationErrorCode::ClientCreateFailed).with_source(error)
        })?;
        let registration_client_uri = registration_client_uri(issuer, client_id)?;

        Ok(DynamicClientRegistrationResponse {
            client_id: client_id.to_string(),
            registration_access_token: Some(registration_access_token),
            registration_client_uri: Some(registration_client_uri),
            client_secret,
            client_secret_expires_at,
            redirect_uris: request.redirect_uris,
            response_types: request.response_types,
            grant_types: request.grant_types,
            application_type: Some(application_type),
            contacts: request.contacts,
            client_name: request.client_name,
            logo_uri: request.logo_uri,
            client_uri: request.client_uri,
            policy_uri: request.policy_uri,
            tos_uri: request.tos_uri,
            sector_identifier_uri: request.sector_identifier_uri,
            subject_type: subject_type.map(|value| value.to_string()),
            id_token_signed_response_alg: request.id_token_signed_response_alg,
            id_token_encrypted_response_alg: request.id_token_encrypted_response_alg,
            id_token_encrypted_response_enc: request.id_token_encrypted_response_enc,
            userinfo_signed_response_alg: request.userinfo_signed_response_alg,
            userinfo_encrypted_response_alg: request.userinfo_encrypted_response_alg,
            userinfo_encrypted_response_enc: request.userinfo_encrypted_response_enc,
            request_object_signing_alg: request.request_object_signing_alg,
            request_object_encryption_alg: request.request_object_encryption_alg,
            request_object_encryption_enc: request.request_object_encryption_enc,
            token_endpoint_auth_method: Some(token_auth_method),
            token_endpoint_auth_signing_alg: request.token_endpoint_auth_signing_alg,
            jwks: request.jwks,
            jwks_uri: request.jwks_uri,
            default_max_age: request.default_max_age,
            require_auth_time: request.require_auth_time,
            default_acr_values: request.default_acr_values,
            initiate_login_uri: request.initiate_login_uri,
            request_uris: request.request_uris,
            post_logout_redirect_uris: request.post_logout_redirect_uris,
            frontchannel_logout_uri: request.frontchannel_logout_uri,
            frontchannel_logout_session_required: request.frontchannel_logout_session_required,
            backchannel_logout_uri: request.backchannel_logout_uri,
            backchannel_logout_session_required: request.backchannel_logout_session_required,
            scope: (!assigned_scopes.is_empty()).then(|| assigned_scopes.join(" ")),
        })
    }

    pub async fn read(
        &self,
        client_id: &str,
        registration_access_token: &str,
        issuer: &Url,
    ) -> Result<DynamicClientRegistrationResponse, AppError> {
        if !*self.enabled.current_value() {
            return Err(AppError::from_code(
                RegistrationErrorCode::DynamicRegistrationDisabled,
            ));
        }

        let client_oid = Uuid::parse_str(client_id).map_err(|_| {
            AppError::from_code(RegistrationErrorCode::InvalidRegistrationAccessToken)
        })?;
        let client = self
            .repo
            .find_by_registration_access_token(client_oid, registration_access_token)
            .await
            .map_err(|error| {
                AppError::from_code(RegistrationErrorCode::ClientLookupFailed).with_source(error)
            })?
            .ok_or_else(|| {
                AppError::from_code(RegistrationErrorCode::InvalidRegistrationAccessToken)
            })?;

        response_from_client(&client, Some(registration_access_token.to_owned()), issuer)
    }

    pub async fn delete(
        &self,
        client_id: &str,
        registration_access_token: &str,
    ) -> Result<(), AppError> {
        if !*self.enabled.current_value() {
            return Err(AppError::from_code(
                RegistrationErrorCode::DynamicRegistrationDisabled,
            ));
        }

        let client_oid = Uuid::parse_str(client_id).map_err(|_| {
            AppError::from_code(RegistrationErrorCode::InvalidRegistrationAccessToken)
        })?;
        let client = self
            .repo
            .find_by_registration_access_token(client_oid, registration_access_token)
            .await
            .map_err(|error| {
                AppError::from_code(RegistrationErrorCode::ClientLookupFailed).with_source(error)
            })?
            .ok_or_else(|| {
                AppError::from_code(RegistrationErrorCode::InvalidRegistrationAccessToken)
            })?;

        self.repo
            .delete_by_oid(client.client().oid)
            .await
            .map_err(|error| {
                AppError::from_code(RegistrationErrorCode::ClientDeleteFailed).with_source(error)
            })?;

        Ok(())
    }
}
