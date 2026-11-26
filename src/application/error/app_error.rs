use std::{
    backtrace::Backtrace,
    error::Error as StdError,
    fmt::{Display, Formatter, Result as FmtResult},
};

use identity_domain::auth::AuthenticationContextClass;

use super::{
    code::AppErrorCode,
    codes::{ErrorCode, common},
    diagnostics::ErrorContext,
    kind::ErrorKind,
    params::ErrorParams,
    validation::ValidationError,
};

/// The current authentication is valid but too weak or too old for the
/// requested operation (RFC 9470 `insufficient_user_authentication`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StepUpChallenge {
    /// Required context class; `None` asks only for fresher authentication.
    pub acr: Option<AuthenticationContextClass>,
    pub max_age_secs: Option<u64>,
}

#[derive(Debug, Default)]
struct AppErrorDetails {
    validation: Option<ValidationError>,
    step_up: Option<StepUpChallenge>,
    /// Scopes the access token lacks (RFC 6750 `insufficient_scope`).
    required_scopes: Vec<String>,
}

#[derive(Debug)]
pub struct AppError {
    code: ErrorCode,
    params: ErrorParams,
    details: Option<Box<AppErrorDetails>>,
    source: Option<Box<dyn StdError + Send + Sync + 'static>>,
    backtrace: Option<Box<Backtrace>>,
}

impl AppError {
    pub fn internal(source: impl StdError + Send + Sync + 'static) -> Self {
        common::error::InternalError.with_source(source)
    }

    /// An unexpected failure at `operation`. Clients receive the generic
    /// internal error; the log keeps the operation, the source and the stack.
    pub fn internal_at(
        operation: &'static str,
        source: impl StdError + Send + Sync + 'static,
    ) -> Self {
        Self::internal(ErrorContext::new(operation, source))
    }

    /// `map_err` adapter for [`Self::internal_at`].
    pub fn map_internal<E: StdError + Send + Sync + 'static>(
        operation: &'static str,
    ) -> impl FnOnce(E) -> Self {
        move |source| Self::internal_at(operation, source)
    }

    /// An internal invariant failed at `operation` without an underlying
    /// error, such as stored data that no longer parses.
    pub fn invariant(operation: &'static str) -> Self {
        Self::internal(ErrorContext::invariant(operation))
    }

    pub(crate) fn from_parts(code: impl Into<ErrorCode>, params: ErrorParams) -> Self {
        let code = code.into();
        Self {
            code,
            params,
            details: None,
            source: None,
            backtrace: (code.kind() == ErrorKind::Internal)
                .then(|| Box::new(Backtrace::force_capture())),
        }
    }

    pub fn with_source(mut self, source: impl StdError + Send + Sync + 'static) -> Self {
        self.source = Some(Box::new(source));
        self
    }

    /// Add a distinct field-level `error` under this summary error, such as
    /// a specific rule failing beneath `ValidationFailed`.
    pub fn with_field_error(
        mut self,
        field: impl Into<String>,
        error: impl Into<AppError>,
    ) -> Self {
        self.push_field_error(field, error.into());
        self
    }

    /// Attribute this error to `field` without changing it. The top-level
    /// code stays this error's own, because clients branch on it, and the
    /// same error is listed for `field` so a form can show it at the input.
    pub fn with_field(mut self, field: impl Into<String>) -> Self {
        let code = self.code;
        let params = self.params.clone();
        self.validation_mut().push_parts(field, code, params);
        self
    }

    pub fn push_field_error(&mut self, field: impl Into<String>, error: AppError) {
        self.validation_mut().push(field, error);
    }

    pub fn kind(&self) -> ErrorKind {
        self.code.kind()
    }

    pub fn code(&self) -> u32 {
        self.code.code()
    }

    pub fn error_code(&self) -> ErrorCode {
        self.code
    }

    pub fn is(&self, code: impl Into<ErrorCode>) -> bool {
        self.code == code.into()
    }

    pub fn backtrace(&self) -> Option<&Backtrace> {
        self.backtrace.as_deref()
    }

    pub fn params(&self) -> &ErrorParams {
        &self.params
    }

    pub fn with_step_up(mut self, challenge: StepUpChallenge) -> Self {
        self.details_mut().step_up = Some(challenge);
        self
    }

    pub fn step_up(&self) -> Option<StepUpChallenge> {
        self.details.as_deref().and_then(|details| details.step_up)
    }

    pub fn with_required_scopes<S: Into<String>>(
        mut self,
        scopes: impl IntoIterator<Item = S>,
    ) -> Self {
        self.details_mut()
            .required_scopes
            .extend(scopes.into_iter().map(Into::into));
        self
    }

    /// Scopes whose absence caused the rejection; empty when none apply.
    pub fn required_scopes(&self) -> &[String] {
        self.details
            .as_deref()
            .map_or(&[], |details| details.required_scopes.as_slice())
    }

    pub fn validation(&self) -> Option<&ValidationError> {
        self.details
            .as_deref()
            .and_then(|details| details.validation.as_ref())
    }

    fn details_mut(&mut self) -> &mut AppErrorDetails {
        self.details
            .get_or_insert_with(|| Box::new(AppErrorDetails::default()))
    }

    fn validation_mut(&mut self) -> &mut ValidationError {
        self.details_mut()
            .validation
            .get_or_insert_with(ValidationError::default)
    }
}

impl Display for AppError {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        write!(f, "[{:?}] error {}", self.kind(), self.code())
    }
}

impl StdError for AppError {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        self.source
            .as_deref()
            .map(|source| source as &(dyn StdError + 'static))
    }
}
