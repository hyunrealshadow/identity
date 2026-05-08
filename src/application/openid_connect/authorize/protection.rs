use super::*;

impl AuthorizeService {
    pub async fn encrypt_login_id(&self, login_oid: Uuid) -> Result<String, AppError> {
        self.data_protector
            .protect("login-id", login_oid.as_bytes())
            .await
            .map_err(|error| {
                AppError::from_code(AuthorizeErrorCode::LoginIdInvalid).with_source(error)
            })
    }

    pub async fn decrypt_login_id(&self, protected_login_id: &str) -> Result<Uuid, AppError> {
        let bytes = self
            .data_protector
            .unprotect("login-id", protected_login_id)
            .await
            .map_err(|error| {
                AppError::from_code(AuthorizeErrorCode::LoginIdInvalid).with_source(error)
            })?;

        Uuid::from_slice(&bytes).map_err(|error| {
            AppError::from_code(AuthorizeErrorCode::LoginIdInvalid).with_source(error)
        })
    }

    pub async fn encrypt_session_id(&self, session_oid: Uuid) -> Result<String, AppError> {
        self.data_protector
            .protect("session-id", session_oid.as_bytes())
            .await
            .map_err(|error| {
                AppError::from_code(AuthorizeErrorCode::StoredSessionIdInvalid).with_source(error)
            })
    }

    pub async fn decrypt_session_id(&self, protected_session_id: &str) -> Result<Uuid, AppError> {
        if let Ok(session_oid) = Uuid::parse_str(protected_session_id) {
            return Ok(session_oid);
        }

        let bytes = self
            .data_protector
            .unprotect("session-id", protected_session_id)
            .await
            .map_err(|error| {
                AppError::from_code(AuthorizeErrorCode::StoredSessionIdInvalid).with_source(error)
            })?;

        Uuid::from_slice(&bytes).map_err(|error| {
            AppError::from_code(AuthorizeErrorCode::StoredSessionIdInvalid).with_source(error)
        })
    }
}
