use std::collections::BTreeSet;

use url::Url;

use super::AppSettings;

/// Exact trusted origins of this installation's first-party applications.
/// Userinfo and malformed settings never become trusted application origins.
#[must_use]
pub fn trusted_application_origins(settings: &AppSettings) -> Vec<String> {
    [
        settings.domain.as_deref(),
        settings.login_domain.as_deref(),
        settings.console_domain.as_deref(),
    ]
    .into_iter()
    .flatten()
    .filter_map(|value| {
        let normalized = if value.contains("://") {
            value.to_owned()
        } else {
            format!("https://{value}")
        };
        let url = Url::parse(&normalized).ok()?;
        (url.scheme() == "https"
            && url.host_str().is_some_and(|host| !host.contains('*'))
            && url.username().is_empty()
            && url.password().is_none()
            && url.query().is_none()
            && url.fragment().is_none())
        .then(|| url.origin().ascii_serialization())
    })
    .collect::<BTreeSet<_>>()
    .into_iter()
    .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keeps_exact_https_origins_and_deduplicates() {
        let settings = AppSettings {
            domain: Some("https://issuer.example:5150/".into()),
            login_domain: Some("https://login.example".into()),
            console_domain: Some("https://login.example/".into()),
            ..Default::default()
        };
        assert_eq!(
            trusted_application_origins(&settings),
            ["https://issuer.example:5150", "https://login.example",]
        );
    }

    #[test]
    fn rejects_unsafe_application_origins() {
        let settings = AppSettings {
            domain: Some("https://user:password@issuer.example".into()),
            login_domain: Some("https://login.example/?anything".into()),
            console_domain: Some("http://console.example".into()),
            ..Default::default()
        };
        assert!(trusted_application_origins(&settings).is_empty());
    }
}
