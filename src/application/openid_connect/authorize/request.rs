use super::AuthorizeService;
use crate::error::{AppError, codes::authorize::AuthorizeErrorCode};
use crate::observability::{BusinessEvent, EventValue};
use chrono::{Duration, Utc};
use identity_domain::{
    client_authorization::{
        ClientAuthorization, ClientAuthorizationData, ClientAuthorizationType,
        StoredAuthorizationRequest,
    },
    openid_connect::{AuthorizationRequest, AuthorizationRequestData},
};
use uuid::Uuid;

impl AuthorizeService {
    pub(super) async fn load_authorization_request_record(
        &self,
        authorization_request_id: Uuid,
    ) -> Result<ClientAuthorization, AppError> {
        let record = self
            .client_authorization_repo
            .find_by_oid(authorization_request_id)
            .await
            .map_err(AppError::map_source(AuthorizeErrorCode::LoadRequestFailed))?
            .ok_or_else(|| AppError::from_code(AuthorizeErrorCode::AuthzRequestNotFound))?;

        if record.type_ != ClientAuthorizationType::AuthorizationRequest {
            return Err(AppError::from_code(
                AuthorizeErrorCode::AuthzRequestTypeMismatch,
            ));
        }

        Ok(record)
    }

    pub(super) fn stored_authorization_request(
        data: ClientAuthorizationData,
    ) -> Result<StoredAuthorizationRequest, AppError> {
        match data {
            ClientAuthorizationData::AuthorizationRequest(stored) => Ok(stored),
            _ => Err(AppError::from_code(
                AuthorizeErrorCode::DeserializeRequestFailed,
            )),
        }
    }

    #[tracing::instrument(skip_all, name = "authorization.request.create")]
    pub async fn create_authorization_request(
        &self,
        request: &AuthorizationRequest,
    ) -> Result<Uuid, AppError> {
        let data = ClientAuthorizationData::AuthorizationRequest(StoredAuthorizationRequest {
            request: AuthorizationRequestData::from(request),
            interaction: Default::default(),
        });

        let record = self
            .client_authorization_repo
            .create(request.client_id, data, Utc::now() + Duration::minutes(10))
            .await
            .map_err(AppError::map_source(AuthorizeErrorCode::StoreRequestFailed))?;
        self.events.emit(
            BusinessEvent::business("authorization.request.created")
                .outcome("success")
                .attribute(
                    "authorization_request_id",
                    EventValue::Text(record.oid.to_string()),
                )
                .attribute(
                    "client_oid",
                    EventValue::Text(request.client_id.to_string()),
                ),
        );

        Ok(record.oid)
    }

    pub async fn load_authorization_request(
        &self,
        authorization_request_id: Uuid,
    ) -> Result<AuthorizationRequestData, AppError> {
        Ok(self
            .load_stored_authorization_request(authorization_request_id)
            .await?
            .request)
    }

    pub async fn load_stored_authorization_request(
        &self,
        authorization_request_id: Uuid,
    ) -> Result<StoredAuthorizationRequest, AppError> {
        let record = self
            .load_authorization_request_record(authorization_request_id)
            .await?;

        Self::stored_authorization_request(record.data)
    }
}
