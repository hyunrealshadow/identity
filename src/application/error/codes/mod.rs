pub mod account;
pub mod administrator;
pub mod auth;
pub mod authorization;
pub mod authorize;
pub mod authorize_http;
pub mod common;
pub mod data_protection;
pub mod device;
pub mod graphql;
pub mod graphql_transport;
pub mod group;
pub mod install;
pub mod key;
pub mod openid_connect;
pub mod provider;
pub mod rbac;
pub mod registration;
pub mod token;
pub mod user_management;

#[cfg(test)]
mod tests {
    use crate::error::code::AppErrorCode;
    use std::{collections::HashSet, ops::RangeInclusive};
    use strum::IntoEnumIterator;

    #[test]
    fn error_codes_are_unique_and_module_scoped() {
        fn check<E: AppErrorCode + IntoEnumIterator>(
            seen: &mut HashSet<u32>,
            range: RangeInclusive<u32>,
        ) {
            let mut nonempty = false;
            for error in E::iter() {
                nonempty = true;
                let code = error.code();
                assert!(range.contains(&code), "{code} outside {range:?}");
                assert!(seen.insert(code), "duplicate error code {code}");
            }
            assert!(nonempty, "empty error registry");
        }
        let mut seen = HashSet::new();
        check::<super::common::CommonErrorCode>(&mut seen, 10000..=10099);
        check::<super::auth::AuthErrorCode>(&mut seen, 11000..=11099);
        check::<super::key::KeyErrorCode>(&mut seen, 12000..=12099);
        check::<super::install::InstallErrorCode>(&mut seen, 13000..=13099);
        check::<super::data_protection::DataProtectionErrorCode>(&mut seen, 14000..=14099);
        check::<super::account::AccountErrorCode>(&mut seen, 15000..=15099);
        check::<super::user_management::UserManagementErrorCode>(&mut seen, 16000..=16099);
        check::<super::rbac::RbacErrorCode>(&mut seen, 17000..=17099);
        check::<super::administrator::AdministratorErrorCode>(&mut seen, 18000..=18019);
        check::<super::group::GroupErrorCode>(&mut seen, 19000..=19099);
        check::<super::provider::ProviderErrorCode>(&mut seen, 20000..=20099);
        check::<super::openid_connect::OpenIdConnectErrorCode>(&mut seen, 21000..=21099);
        check::<super::authorize_http::AuthorizeHttpErrorCode>(&mut seen, 22000..=22099);
        check::<super::authorize::AuthorizeErrorCode>(&mut seen, 23000..=23099);
        check::<super::token::TokenErrorCode>(&mut seen, 24000..=24099);
        check::<super::registration::RegistrationErrorCode>(&mut seen, 25000..=25099);
        check::<super::device::DeviceAuthorizationErrorCode>(&mut seen, 26000..=26099);
        check::<super::authorization::AuthorizationErrorCode>(&mut seen, 27000..=27099);
        check::<super::graphql_transport::GraphqlTransportErrorCode>(&mut seen, 28100..=28199);
        check::<super::graphql::GraphqlErrorCode>(&mut seen, 28000..=28099);
    }
}
