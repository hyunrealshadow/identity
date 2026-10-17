use super::AuthorizeService;
use crate::error::{AppError, codes::authorize::AuthorizeErrorCode};
use crate::observability::{BusinessEvent, EventValue};
use chrono::Utc;
use identity_domain::{
    auth::model::Login,
    client::model::ClientOid,
    client_authorization::ConsentState,
    openid_connect::{AuthorizationRequestData, OpenIdConnectClient, ScopeSet},
};
use uuid::Uuid;

impl AuthorizeService {
    pub async fn load_consent_context(
        &self,
        authorization_request_id: Uuid,
    ) -> Result<(AuthorizationRequestData, OpenIdConnectClient), AppError> {
        let request = self
            .load_authorization_request(authorization_request_id)
            .await?;
        let client_id = Uuid::parse_str(&request.client_id).map_err(AppError::map_source(
            AuthorizeErrorCode::StoredClientIdInvalid,
        ))?;
        let client = self
            .client_repo
            .find_by_oid(client_id)
            .await
            .map_err(AppError::map_source(AuthorizeErrorCode::ClientLookupFailed))?
            .ok_or_else(|| AppError::from_code(AuthorizeErrorCode::ClientNotFound))?;

        Ok((request, client))
    }

    pub async fn load_consent_context_by_login(
        &self,
        protected_login_oid: &str,
    ) -> Result<(Login, AuthorizationRequestData, OpenIdConnectClient), AppError> {
        let login = self.load_login_by_protected_id(protected_login_oid).await?;
        let (request, client) = self
            .load_consent_context(login.client_authorization_oid)
            .await?;
        Ok((login, request, client))
    }

    pub async fn record_consent_by_login(
        &self,
        protected_login_oid: &str,
        consent_state: ConsentState,
    ) -> Result<(), AppError> {
        let login = self.load_login_by_protected_id(protected_login_oid).await?;
        self.record_consent_decision(login.client_authorization_oid, consent_state)
            .await
    }

    pub async fn user_consented_scope_names(
        &self,
        user_oid: Uuid,
        client_oid: ClientOid,
    ) -> Result<Vec<String>, AppError> {
        self.client_authorization_repo
            .user_consented_scope_names(user_oid, client_oid)
            .await
            .map_err(AppError::map_source(AuthorizeErrorCode::LoadRequestFailed))
    }

    pub async fn has_user_consent(
        &self,
        user_oid: Uuid,
        client_oid: ClientOid,
        requested_scope: &str,
    ) -> Result<bool, AppError> {
        let requested_scope = ScopeSet::parse(requested_scope).map_err(AppError::map_source(
            AuthorizeErrorCode::DeserializeRequestFailed,
        ))?;
        self.client_authorization_repo
            .has_user_consent(user_oid, client_oid, &requested_scope)
            .await
            .map_err(AppError::map_source(AuthorizeErrorCode::LoadRequestFailed))
    }

    #[tracing::instrument(skip_all, name = "consent.record")]
    pub async fn record_consent_decision(
        &self,
        authorization_request_id: Uuid,
        consent_state: ConsentState,
    ) -> Result<(), AppError> {
        let decision = match consent_state {
            ConsentState::Approved => "granted",
            ConsentState::Denied => "denied",
            _ => "recorded",
        };
        let updated = self
            .client_authorization_repo
            .record_authorization_request_consent(
                authorization_request_id,
                consent_state,
                Utc::now(),
            )
            .await
            .map_err(AppError::map_source(AuthorizeErrorCode::StoreRequestFailed))?;

        if !updated {
            return Err(Self::interaction_conflict());
        }

        self.events.emit(
            BusinessEvent::business("consent.decision")
                .outcome(decision)
                .attribute(
                    "authorization_request_id",
                    EventValue::Text(authorization_request_id.to_string()),
                ),
        );

        Ok(())
    }
}
