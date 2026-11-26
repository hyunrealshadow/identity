use super::{AppError, ErrorCode, code::AppErrorCode as _, params::ErrorParams};

#[derive(Debug, Default)]
pub struct ValidationError {
    fields: Vec<FieldValidationError>,
}

impl ValidationError {
    pub fn push(&mut self, field: impl Into<String>, error: AppError) {
        self.push_parts(field, error.error_code(), error.params().clone());
    }

    pub fn push_parts(
        &mut self,
        field: impl Into<String>,
        code: impl Into<ErrorCode>,
        params: ErrorParams,
    ) {
        self.fields.push(FieldValidationError {
            field: field.into(),
            code: code.into(),
            params,
        });
    }

    pub fn fields(&self) -> &[FieldValidationError] {
        &self.fields
    }

    pub fn is_empty(&self) -> bool {
        self.fields.is_empty()
    }
}

#[derive(Debug)]
pub struct FieldValidationError {
    field: String,
    code: ErrorCode,
    params: ErrorParams,
}

impl FieldValidationError {
    pub fn field(&self) -> &str {
        &self.field
    }

    pub fn code(&self) -> u32 {
        self.code.code()
    }

    pub fn error_code(&self) -> ErrorCode {
        self.code
    }

    pub fn params(&self) -> &ErrorParams {
        &self.params
    }
}
