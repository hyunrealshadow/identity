use std::{
    backtrace::Backtrace,
    error::Error,
    fmt::{Display, Formatter, Result as FmtResult},
};

use super::AppError;

/// Captures the stack at the operation that failed, before application wrapping.
#[derive(Debug)]
pub struct ErrorContext {
    operation: &'static str,
    backtrace: Backtrace,
    source: Box<dyn Error + Send + Sync>,
}

impl ErrorContext {
    pub fn new(operation: &'static str, source: impl Error + Send + Sync + 'static) -> Self {
        Self {
            operation,
            backtrace: Backtrace::force_capture(),
            source: Box::new(source),
        }
    }
}

impl Display for ErrorContext {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        f.write_str(self.operation)
    }
}

impl Error for ErrorContext {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        Some(self.source.as_ref())
    }
}

pub struct ErrorDiagnostics<'a> {
    pub cause: String,
    pub operation: Option<&'static str>,
    pub backtrace: Option<&'a Backtrace>,
}

impl<'a> ErrorDiagnostics<'a> {
    /// Preserves the innermost captured stack and the underlying cause.
    pub fn from_error(error: &'a (dyn Error + 'static)) -> Self {
        let mut diagnostics = Self {
            cause: error.to_string(),
            operation: None,
            backtrace: None,
        };
        let mut current = Some(error);
        while let Some(error) = current {
            if let Some(context) = error.downcast_ref::<ErrorContext>() {
                diagnostics.operation = Some(context.operation);
                diagnostics.backtrace = Some(&context.backtrace);
            } else if let Some(error) = error.downcast_ref::<AppError>()
                && let Some(backtrace) = error.backtrace()
            {
                diagnostics.backtrace = Some(backtrace);
            }
            diagnostics.cause = error.to_string();
            current = error.source();
        }
        diagnostics
    }
}

#[cfg(test)]
mod tests {
    use std::{backtrace::BacktraceStatus, io::Error, ptr};

    use crate::error::codes::common::CommonErrorCode;

    use super::*;

    #[test]
    fn application_wrapping_preserves_the_original_stack() {
        let query = ErrorContext::new(
            "client_authorization.lock_refresh_family",
            Error::other("syntax error at or near dot"),
        );
        let query_trace = query.backtrace.to_string();
        let error = AppError::from_code(CommonErrorCode::InternalError).with_source(query);
        let diagnostics = ErrorDiagnostics::from_error(&error);
        assert_eq!(diagnostics.cause, "syntax error at or near dot");
        assert_eq!(
            diagnostics.operation,
            Some("client_authorization.lock_refresh_family")
        );
        assert_eq!(
            diagnostics.backtrace.unwrap().status(),
            BacktraceStatus::Captured
        );
        assert_eq!(diagnostics.backtrace.unwrap().to_string(), query_trace);
        assert!(!ptr::eq(
            diagnostics.backtrace.unwrap(),
            error.backtrace().unwrap()
        ));
    }

    #[test]
    fn internal_errors_without_a_source_have_a_stack_but_business_rejections_do_not() {
        let error = AppError::from_code(CommonErrorCode::InternalError);
        let diagnostics = ErrorDiagnostics::from_error(&error);
        assert!(ptr::eq(
            diagnostics.backtrace.unwrap(),
            error.backtrace().unwrap()
        ));
        assert_eq!(
            diagnostics.backtrace.unwrap().status(),
            BacktraceStatus::Captured
        );
        assert!(
            AppError::from_code(CommonErrorCode::Unauthorized)
                .backtrace()
                .is_none()
        );
    }
}
