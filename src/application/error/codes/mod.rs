pub mod account;
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
    use super::{
        account::AccountErrorCode, auth::AuthErrorCode, authorization::AuthorizationErrorCode,
        authorize::AuthorizeErrorCode, authorize_http::AuthorizeHttpErrorCode,
        common::CommonErrorCode, data_protection::DataProtectionErrorCode,
        device::DeviceAuthorizationErrorCode, graphql::GraphqlErrorCode,
        graphql_transport::GraphqlTransportErrorCode, group::GroupErrorCode,
        install::InstallErrorCode, key::KeyErrorCode, openid_connect::OpenIdConnectErrorCode,
        provider::ProviderErrorCode, rbac::RbacErrorCode, registration::RegistrationErrorCode,
        token::TokenErrorCode, user_management::UserManagementErrorCode,
    };
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
        check::<CommonErrorCode>(&mut seen, 10000..=10099);
        check::<AuthErrorCode>(&mut seen, 11000..=11099);
        check::<KeyErrorCode>(&mut seen, 12000..=12099);
        check::<InstallErrorCode>(&mut seen, 13000..=13099);
        check::<DataProtectionErrorCode>(&mut seen, 14000..=14099);
        check::<AccountErrorCode>(&mut seen, 15000..=15099);
        check::<UserManagementErrorCode>(&mut seen, 16000..=16099);
        check::<RbacErrorCode>(&mut seen, 17000..=17099);
        check::<GroupErrorCode>(&mut seen, 19000..=19099);
        check::<ProviderErrorCode>(&mut seen, 20000..=20099);
        check::<OpenIdConnectErrorCode>(&mut seen, 21000..=21099);
        check::<AuthorizeHttpErrorCode>(&mut seen, 22000..=22099);
        check::<AuthorizeErrorCode>(&mut seen, 23000..=23099);
        check::<TokenErrorCode>(&mut seen, 24000..=24099);
        check::<RegistrationErrorCode>(&mut seen, 25000..=25099);
        check::<DeviceAuthorizationErrorCode>(&mut seen, 26000..=26099);
        check::<AuthorizationErrorCode>(&mut seen, 27000..=27099);
        check::<GraphqlTransportErrorCode>(&mut seen, 28100..=28199);
        check::<GraphqlErrorCode>(&mut seen, 28000..=28099);
    }
}
