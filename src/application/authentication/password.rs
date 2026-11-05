use std::sync::{Arc, OnceLock};

use tokio::{sync::Semaphore, task::spawn_blocking};

use crate::error::AppError;

pub use super::hash::{HashOptions, PasswordHashError, PasswordHasher, VerifyResult};

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
        .map_err(AppError::internal)?;

    spawn_blocking(move || {
        let _permit = permit;
        operation()
    })
    .await
    .map_err(AppError::internal)?
    .map_err(AppError::from)
}
