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
}
