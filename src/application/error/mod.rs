#[macro_use]
mod macros;

pub mod app_error;
pub mod catalog;
pub mod code;
pub mod codes;
pub mod diagnostics;
pub mod kind;
pub mod params;
pub mod validation;

pub use app_error::AppError;
pub use codes::ErrorCode;
pub use diagnostics::{ErrorContext, ErrorDiagnostics};
pub use validation::{FieldValidationError, ValidationError};
