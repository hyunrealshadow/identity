use crate::setting::SettingDefinition;

/// Domain this installation is served from, as given during installation.
///
/// It defines the issuer and every URL the identity service itself owns, such
/// as the device verification page (`{domain}/device`).
pub struct DomainSetting;

impl SettingDefinition for DomainSetting {
    type Value = Option<String>;

    const KEY: &'static str = "app.domain";

    fn default_value() -> Self::Value {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::DomainSetting;
    use crate::setting::SettingDefinition;

    #[test]
    fn the_domain_is_unset_until_installation() {
        assert_eq!(DomainSetting::KEY, "app.domain");
        assert!(DomainSetting::default_value().is_none());
    }
}
