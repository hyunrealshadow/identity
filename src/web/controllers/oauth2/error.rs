use std::borrow::Cow;

use http::StatusCode;
use identity_application::error::{AppError, kind::ErrorKind};

/// Opt-in error projection at OAuth protocol boundaries. Each endpoint owns
/// its error-code policy; application errors do not implement this trait.
pub(super) trait Rfc6749Error {
    fn app_error(&self) -> &AppError;

    fn rfc6749_error_code(&self) -> Cow<'static, str>;

    fn rfc6749_status(&self) -> StatusCode {
        if self.app_error().kind() == ErrorKind::Internal {
            StatusCode::INTERNAL_SERVER_ERROR
        } else if self.rfc6749_error_code() == "invalid_client" {
            StatusCode::UNAUTHORIZED
        } else {
            StatusCode::BAD_REQUEST
        }
    }
}
