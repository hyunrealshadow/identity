use std::{
    backtrace::Backtrace,
    error::Error as StdError,
    fmt::{Display, Formatter, Result as FmtResult},
};

use identity_domain::auth::AuthenticationContextClass;

use super::{
    code::AppErrorCode,
    codes::{ErrorCode, common},
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

    pub fn with_field_error(
        mut self,
        field: impl Into<String>,
        error: impl Into<AppError>,
    ) -> Self {
        self.push_field_error(field, error.into());
        self
    }

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
