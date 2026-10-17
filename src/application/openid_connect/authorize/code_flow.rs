use super::AuthorizeService;
use super::implicit_flow::AuthenticationContext;
use crate::error::{AppError, codes::authorize::AuthorizeErrorCode};
use crate::{
    observability::{BusinessEvent, EventValue},
    openid_connect::session::calculate_session_state,
};
use chrono::{Duration, Utc};
use identity_domain::{
    auth::SessionOid,
    client_authorization::{AuthorizationCodeData, ClientAuthorizationData},
    openid_connect::AuthorizationRequestData,
};
use url::Url;
use uuid::Uuid;

#[derive(Clone, Copy)]
pub(super) struct AuthorizationCodeContext<'a> {
    pub authorization_request_id: Uuid,
    pub user_oid: Uuid,
    pub session_oid: SessionOid,
    pub protected_session_id: &'a str,
    pub authentication: AuthenticationContext<'a>,
}

impl AuthorizeService {
    pub(super) async fn approve_code_flow(
        &self,
        request: &AuthorizationRequestData,
        context: AuthorizationCodeContext<'_>,
    ) -> Result<Url, AppError> {
        let redirect_uri = Url::parse(&request.redirect_uri).map_err(AppError::map_source(
            AuthorizeErrorCode::StoredRedirectUriInvalid,
        ))?;

        let (protected_code, _) = self.create_authorization_code(request, context).await?;

        let mut redirect = redirect_uri;
        redirect
            .query_pairs_mut()
            .append_pair("code", &protected_code)
            .append_pair("state", &request.state)
            .append_pair("iss", self.provider_service.issuer()?.as_str())
            .append_pair(
                "session_state",
                &session_state_for_authorize_response(request, context.protected_session_id)?,
            );

        Ok(redirect)
    }

    pub(super) async fn create_authorization_code(
        &self,
        request: &AuthorizationRequestData,
        context: AuthorizationCodeContext<'_>,
    ) -> Result<(String, Uuid), AppError> {
        let AuthorizationCodeContext {
            authorization_request_id,
            user_oid,
            session_oid,
            protected_session_id,
            authentication,
        } = context;
        let record = self
            .client_authorization_repo
            .create(
                Uuid::parse_str(&request.client_id).map_err(AppError::map_source(
                    AuthorizeErrorCode::StoredClientIdInvalid,
                ))?,
                ClientAuthorizationData::AuthorizationCode(AuthorizationCodeData {
                    scope: request.scope.clone(),
                    resources: request.resources.clone(),
                    nonce: request.nonce.clone(),
                    code_challenge: request.code_challenge.clone(),
                    code_challenge_method: request.code_challenge_method,
                    user_oid: user_oid.to_string(),
                    session_oid,
                    protected_session_id: Some(protected_session_id.to_string()),
                    acr: authentication.acr.map(str::to_owned),
                    amr: authentication.amr.to_vec(),
                    redirect_uri: request.redirect_uri.clone(),
                    redirect_uri_was_supplied: request.redirect_uri_was_supplied,
                    auth_time: authentication.auth_time,
                    claims: request
                        .claims
                        .as_deref()
                        .map(Self::parse_claims_request)
                        .transpose()?,
                }),
                Utc::now() + Duration::minutes(10),
            )
            .await
            .map_err(AppError::map_source(AuthorizeErrorCode::StoreCodeFailed))?;

        let protected_code = self
            .data_protector
            .protect("authorization-code", record.oid.as_bytes())
            .await
            .map_err(AppError::map_source(AuthorizeErrorCode::StoreCodeFailed))?;

        self.events.emit(
            BusinessEvent::business("authorization_code.created")
                .outcome("success")
                .attribute(
                    "authorization_request_id",
                    EventValue::Text(authorization_request_id.to_string()),
                )
                .attribute(
                    "authorization_code_id",
                    EventValue::Text(record.oid.to_string()),
                )
                .attribute(
                    "client_oid",
                    EventValue::Text(record.client_oid.to_string()),
                )
                .attribute(
                    "user_oid",
                    EventValue::Pseudonymized {
                        purpose: "user_oid",
                        value: user_oid.to_string(),
                    },
                )
                .attribute(
                    "session_oid",
                    EventValue::Pseudonymized {
                        purpose: "session_oid",
                        value: session_oid.0.to_string(),
                    },
                ),
        );

        Ok((protected_code, record.oid))
    }
}

pub(super) fn session_state_for_authorize_response(
    request: &AuthorizationRequestData,
    protected_session_id: &str,
) -> Result<String, AppError> {
    let redirect_uri = Url::parse(&request.redirect_uri).map_err(AppError::map_source(
        AuthorizeErrorCode::StoredRedirectUriInvalid,
    ))?;
    let origin = redirect_uri.origin().ascii_serialization();
    Ok(calculate_session_state(
        &request.client_id,
        &origin,
        protected_session_id,
        protected_session_id,
    ))
}
