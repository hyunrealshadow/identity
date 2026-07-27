use std::sync::{Arc, OnceLock};

use identity_domain::auth::password::PasswordHashError;
use tokio::sync::Semaphore;

use crate::error::{AppError, codes::common::CommonErrorCode};

const MAX_CONCURRENT_PASSWORD_HASHES: usize = 4;

fn password_hash_semaphore() -> Arc<Semaphore> {
    static SEMAPHORE: OnceLock<Arc<Semaphore>> = OnceLock::new();
    Arc::clone(SEMAPHORE.get_or_init(|| Arc::new(Semaphore::new(MAX_CONCURRENT_PASSWORD_HASHES))))
}

pub(crate) async fn run_password_hashing<T, F>(operation: F) -> Result<T, AppError>
where
    T: Send + 'static,
    F: FnOnce() -> Result<T, PasswordHashError> + Send + 'static,
{
    let permit = password_hash_semaphore()
        .acquire_owned()
        .await
        .map_err(|error| AppError::from_code(CommonErrorCode::InternalError).with_source(error))?;

    tokio::task::spawn_blocking(move || {
        let _permit = permit;
        operation()
    })
    .await
    .map_err(|error| AppError::from_code(CommonErrorCode::InternalError).with_source(error))?
    .map_err(AppError::from)
}
