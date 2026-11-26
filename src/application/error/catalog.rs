use super::{
    code::AppErrorCode,
    codes::{
        account::AccountErrorCode, audit::AuditErrorCode, auth::AuthErrorCode,
        authorization::AuthorizationErrorCode, authorize::AuthorizeErrorCode,
        client::ClientErrorCode, common::CommonErrorCode, device::DeviceAuthorizationErrorCode,
        graphql::GraphqlErrorCode, graphql_transport::GraphqlTransportErrorCode,
        group::GroupErrorCode, instance::InstanceErrorCode, openid_connect::OpenIdConnectErrorCode,
        rbac::RbacErrorCode, token::TokenErrorCode, user_management::UserManagementErrorCode,
    },
    kind::ErrorKind,
};

#[derive(Debug, Clone)]
pub struct PublicErrorDefinition {
    pub code: u32,
    pub kind: ErrorKind,
    pub fluent_key: String,
    pub usage_module: &'static str,
    pub required: &'static [&'static str],
    pub optional: &'static [&'static str],
}

/// Authoritative inventory of every public application error code.
/// Generated directly from the typed error code definitions.
#[must_use]
pub fn public_error_inventory() -> Vec<PublicErrorDefinition> {
    fn definitions<C: AppErrorCode + strum::IntoEnumIterator>() -> Vec<PublicErrorDefinition> {
        C::iter()
            .map(|code| PublicErrorDefinition {
                code: code.code(),
                kind: code.kind(),
                fluent_key: format!("E{}", code.code()),
                usage_module: code
                    .usage_module()
                    .expect("public error code must declare usage_module"),
                required: code.required_params(),
                optional: code.optional_params(),
            })
            .collect()
    }

    let mut inventory = definitions::<CommonErrorCode>();
    inventory.extend(definitions::<AuthErrorCode>());
    inventory.extend(definitions::<AccountErrorCode>());
    inventory.extend(definitions::<AuthorizeErrorCode>());
    inventory.extend(definitions::<DeviceAuthorizationErrorCode>());
    inventory.extend(definitions::<TokenErrorCode>());
    inventory.extend(definitions::<OpenIdConnectErrorCode>());
    inventory.extend(definitions::<GraphqlErrorCode>());
    inventory.extend(definitions::<GraphqlTransportErrorCode>());
    inventory.extend(definitions::<AuthorizationErrorCode>());
    inventory.extend(definitions::<UserManagementErrorCode>());
    inventory.extend(definitions::<RbacErrorCode>());
    inventory.extend(definitions::<ClientErrorCode>());
    inventory.extend(definitions::<InstanceErrorCode>());
    inventory.extend(definitions::<GroupErrorCode>());
    inventory.extend(definitions::<AuditErrorCode>());
    inventory
}
