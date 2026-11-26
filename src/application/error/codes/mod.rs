pub mod account;
pub mod audit;
pub mod auth;
pub mod authorization;
pub mod authorize;
pub mod authorize_http;
pub mod client;
pub mod common;
pub mod data_protection;
pub mod device;
pub mod graphql;
pub mod graphql_transport;
pub mod group;
pub mod install;
pub mod instance;
pub mod key;
pub mod openid_connect;
pub mod provider;
pub mod rbac;
pub mod registration;
pub mod token;
pub mod user_management;

crate::define_error_code_registry! {
    Common(common::CommonErrorCode) in 10000..=10099,
    Auth(auth::AuthErrorCode) in 11000..=11099,
    Key(key::KeyErrorCode) in 12000..=12099,
    Install(install::InstallErrorCode) in 13000..=13099,
    DataProtection(data_protection::DataProtectionErrorCode) in 14000..=14099,
    Account(account::AccountErrorCode) in 15000..=15099,
    UserManagement(user_management::UserManagementErrorCode) in 16000..=16099,
    Rbac(rbac::RbacErrorCode) in 17000..=17099,
    Client(client::ClientErrorCode) in 18000..=18099,
    Group(group::GroupErrorCode) in 19000..=19099,
    Provider(provider::ProviderErrorCode) in 20000..=20099,
    OpenIdConnect(openid_connect::OpenIdConnectErrorCode) in 21000..=21099,
    AuthorizeHttp(authorize_http::AuthorizeHttpErrorCode) in 22000..=22099,
    Authorize(authorize::AuthorizeErrorCode) in 23000..=23099,
    Token(token::TokenErrorCode) in 24000..=24099,
    Registration(registration::RegistrationErrorCode) in 25000..=25099,
    Device(device::DeviceAuthorizationErrorCode) in 26000..=26099,
    Authorization(authorization::AuthorizationErrorCode) in 27000..=27099,
    Graphql(graphql::GraphqlErrorCode) in 28000..=28099,
    GraphqlTransport(graphql_transport::GraphqlTransportErrorCode) in 28100..=28199,
    Instance(instance::InstanceErrorCode) in 29000..=29099,
    Audit(audit::AuditErrorCode) in 30000..=30099,
}

#[cfg(test)]
mod tests {
    use super::ErrorCode;
    use crate::error::code::AppErrorCode;
    use std::collections::HashSet;

    #[test]
    fn error_codes_are_unique_and_module_scoped() {
        let all = ErrorCode::all();
        assert!(!all.is_empty(), "empty error registry");
        let mut seen = HashSet::new();
        for error in all {
            let code = error.code();
            let range = error.range();
            assert!(range.contains(&code), "{code} outside {range:?}");
            assert!(seen.insert(code), "duplicate error code {code}");
        }
    }
}
