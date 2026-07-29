use super::{AppError, params::ErrorParams};

#[derive(Debug, Default)]
pub struct ValidationError {
    fields: Vec<FieldValidationError>,
}

impl ValidationError {
    pub fn push(&mut self, field: impl Into<String>, error: AppError) {
        self.push_parts(field, error.code(), error.params().clone());
    }

    pub fn push_parts(&mut self, field: impl Into<String>, code: u32, params: ErrorParams) {
        self.fields.push(FieldValidationError {
            field: field.into(),
            code,
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
    code: u32,
    params: ErrorParams,
}

impl FieldValidationError {
    pub fn field(&self) -> &str {
        &self.field
    }

    pub fn code(&self) -> u32 {
        self.code
    }

    pub fn params(&self) -> &ErrorParams {
        &self.params
    }
}
