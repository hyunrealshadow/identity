use crate::setting::SettingDefinition;

/// Where the login application is served, derived from the application URL
/// given during installation (`https://login.example.com/login` becomes
/// `https://login.example.com`).
///
/// The login application owns the user facing pages — sign-in, consent and
/// device verification — which may live on a different host than the identity
/// service itself, so its origin is recorded on its own.
pub struct LoginDomainSetting;

impl SettingDefinition for LoginDomainSetting {
    type Value = Option<String>;

    const KEY: &'static str = "app.login_domain";

    fn default_value() -> Self::Value {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::LoginDomainSetting;
    use crate::setting::SettingDefinition;

    #[test]
    fn the_login_domain_is_unset_until_installation() {
        assert_eq!(LoginDomainSetting::KEY, "app.login_domain");
        assert!(LoginDomainSetting::default_value().is_none());
    }
}
