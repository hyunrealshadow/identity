use serde::Deserialize;
use url::Url;

/// Explicit opt-in for provisioning the protected, secretless browser client.
#[derive(Clone, Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConsoleConfig {
    #[serde(default)]
    pub enabled: bool,
    pub origin: Option<String>,
}

impl ConsoleConfig {
    pub fn validated_origin(&self) -> Result<Option<String>, &'static str> {
        if !self.enabled {
            return Ok(None);
        }
        let raw = self
            .origin
            .as_deref()
            .ok_or("console.origin is required when console is enabled")?;
        let url = Url::parse(raw).map_err(|_| "console.origin must be an HTTPS origin")?;
        if url.scheme() != "https"
            || url.host_str().is_none()
            || !url.username().is_empty()
            || url.password().is_some()
            || url.query().is_some()
            || url.fragment().is_some()
            || url.path() != "/"
            || raw.trim_end_matches('/') != url.origin().ascii_serialization()
        {
            return Err(
                "console.origin must be an exact HTTPS origin without credentials, path, query or fragment",
            );
        }
        Ok(Some(url.origin().ascii_serialization()))
    }
}

#[cfg(test)]
mod tests {
    use super::ConsoleConfig;

    #[test]
    fn provisioning_requires_an_explicit_exact_https_origin() {
        for origin in [
            "http://localhost:3001",
            "https://console.example/other",
            "https://a@console.example",
            "https://console.example?x=1",
            "https://console.example#fragment",
            "https://console.example.evil/../",
        ] {
            assert!(
                ConsoleConfig {
                    enabled: true,
                    origin: Some(origin.into())
                }
                .validated_origin()
                .is_err(),
                "{origin}"
            );
        }
        assert_eq!(
            ConsoleConfig {
                enabled: true,
                origin: Some("https://localhost:3001".into())
            }
            .validated_origin()
            .unwrap()
            .as_deref(),
            Some("https://localhost:3001")
        );
        assert!(
            ConsoleConfig::default()
                .validated_origin()
                .unwrap()
                .is_none()
        );
    }
}
