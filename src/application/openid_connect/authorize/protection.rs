use identity_domain::auth::SessionOid;

use super::*;

impl AuthorizeService {
    pub async fn encrypt_login_id(&self, login_oid: Uuid) -> Result<String, AppError> {
        self.data_protector
            .protect("login-id", login_oid.as_bytes())
            .await
            .map_err(AppError::map_source(AuthorizeErrorCode::LoginIdInvalid))
    }

    pub async fn decrypt_login_id(&self, protected_login_id: &str) -> Result<Uuid, AppError> {
        let bytes = self
            .data_protector
            .unprotect("login-id", protected_login_id)
            .await
            .map_err(AppError::map_source(AuthorizeErrorCode::LoginIdInvalid))?;

        Uuid::from_slice(&bytes).map_err(AppError::map_source(AuthorizeErrorCode::LoginIdInvalid))
    }

    pub async fn encrypt_session_id(&self, session_oid: SessionOid) -> Result<String, AppError> {
        self.data_protector
            .protect("session-id", Uuid::from(session_oid).as_bytes())
            .await
            .map_err(AppError::map_source(
                AuthorizeErrorCode::StoredSessionIdInvalid,
            ))
    }

    pub async fn decrypt_session_id(
        &self,
        protected_session_id: &str,
    ) -> Result<SessionOid, AppError> {
        if let Ok(session_oid) = Uuid::parse_str(protected_session_id) {
            return Ok(SessionOid(session_oid));
        }

        let bytes = self
            .data_protector
            .unprotect("session-id", protected_session_id)
            .await
            .map_err(AppError::map_source(
                AuthorizeErrorCode::StoredSessionIdInvalid,
            ))?;

        Uuid::from_slice(&bytes)
            .map(SessionOid)
            .map_err(AppError::map_source(
                AuthorizeErrorCode::StoredSessionIdInvalid,
            ))
    }
}
