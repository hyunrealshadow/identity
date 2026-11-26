use super::{code::AppErrorCode, codes::ErrorCode, kind::ErrorKind};

#[derive(Debug, Clone)]
pub struct PublicErrorDefinition {
    pub code: u32,
    pub group: &'static str,
    pub name: &'static str,
    pub kind: ErrorKind,
    pub fluent_key: String,
    pub usage_module: &'static str,
    pub required: &'static [&'static str],
    pub optional: &'static [&'static str],
}

/// Authoritative inventory of every registered application error code.
/// Generated directly from the closed [`ErrorCode`] registry.
#[must_use]
pub fn public_error_inventory() -> Vec<PublicErrorDefinition> {
    ErrorCode::all()
        .into_iter()
        .map(|code| PublicErrorDefinition {
            code: code.code(),
            group: code.group(),
            name: code.name(),
            kind: code.kind(),
            fluent_key: format!("E{}", code.code()),
            usage_module: code
                .usage_module()
                .expect("every registered error code must declare usage_module"),
            required: code.required_params(),
            optional: code.optional_params(),
        })
        .collect()
}
