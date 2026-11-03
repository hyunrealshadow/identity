//! Pwned Passwords range API: only five SHA-1 hex characters leave the process.
use async_trait::async_trait;
use identity_application::{
    auth::password_policy::BreachedPasswordChecker,
    error::{AppError, codes::auth::AuthErrorCode},
};
use openssl::sha;
use reqwest::{Client, StatusCode, Url, redirect::Policy};
use std::{env, error::Error, io::Error as IoError, str, time::Duration};
use tokio::sync::Semaphore;

pub struct PwnedPasswordChecker {
    client: Client,
    endpoint: Url,
    requests: Semaphore,
}

impl PwnedPasswordChecker {
    pub fn new() -> Result<Self, Box<dyn Error + Send + Sync>> {
        let endpoint = Url::parse(
            &env::var("IDENTITY_PWNED_PASSWORDS_URL")
                .unwrap_or_else(|_| "https://api.pwnedpasswords.com/range/".to_owned()),
        )?;
        let client = Client::builder()
            .https_only(true)
            .redirect(Policy::none())
            .timeout(Duration::from_secs(3))
            .connect_timeout(Duration::from_secs(2))
            .user_agent("Identity-Password-Policy")
            .build()?;
        Self::with_http_client(client, endpoint)
    }

    /// Construct a checker using an explicitly managed HTTPS transport.
    pub fn with_http_client(
        client: Client,
        endpoint: Url,
    ) -> Result<Self, Box<dyn Error + Send + Sync>> {
        if endpoint.scheme() != "https"
            || !endpoint.path().ends_with('/')
            || !endpoint.username().is_empty()
            || endpoint.password().is_some()
            || endpoint.query().is_some()
            || endpoint.fragment().is_some()
        {
            return Err(IoError::other("IDENTITY_PWNED_PASSWORDS_URL must be an HTTPS base URL ending in / without credentials, query or fragment").into());
        }
        Ok(Self {
            client,
            endpoint,
            requests: Semaphore::new(4),
        })
    }
}

fn unavailable() -> AppError {
    AppError::from_code(AuthErrorCode::PasswordCheckUnavailable)
}

#[async_trait]
impl BreachedPasswordChecker for PwnedPasswordChecker {
    async fn is_breached(&self, password: &str) -> Result<bool, AppError> {
        let _permit = self.requests.try_acquire().map_err(|_| unavailable())?;
        // SHA-1 is used only for range lookup, never for password storage.
        let digest = sha::sha1(password.as_bytes());
        let hash: String = digest.iter().map(|byte| format!("{byte:02X}")).collect();
        let url = self.endpoint.join(&hash[..5]).map_err(|_| unavailable())?;
        let mut response = self
            .client
            .get(url)
            .header("Add-Padding", "true")
            .send()
            .await
            .map_err(|_| unavailable())?;
        if response.status() != StatusCode::OK {
            return Err(unavailable());
        }
        let mut body = Vec::new();
        while let Some(chunk) = response.chunk().await.map_err(|_| unavailable())? {
            if body.len() + chunk.len() > 2 * 1024 * 1024 {
                return Err(unavailable());
            }
            body.extend_from_slice(&chunk);
        }
        let body = str::from_utf8(&body).map_err(|_| unavailable())?;
        parse_range(body, &hash[5..])
    }
}

fn parse_range(body: &str, suffix: &str) -> Result<bool, AppError> {
    let mut lines = 0;
    let mut breached = false;
    for line in body.lines() {
        let (candidate, count) = line.split_once(':').ok_or_else(unavailable)?;
        if candidate.len() != 35 || !candidate.bytes().all(|c| c.is_ascii_hexdigit()) {
            return Err(unavailable());
        }
        let count: u64 = count.parse().map_err(|_| unavailable())?;
        breached |= candidate.eq_ignore_ascii_case(suffix) && count > 0;
        lines += 1;
    }
    if lines == 0 {
        return Err(unavailable());
    }
    Ok(breached)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn padding_is_not_a_breach_and_malformed_results_fail_closed() {
        let suffix = "A".repeat(35);
        assert!(!parse_range(&format!("{suffix}:0\r\n"), &suffix).unwrap());
        assert!(parse_range(&format!("{suffix}:42\r\n"), &suffix).unwrap());
        assert!(!parse_range(&format!("{}:42", "B".repeat(35)), &suffix).unwrap());
        for body in ["", "<html>upstream error</html>", "ABC:1"] {
            assert!(parse_range(body, &suffix).is_err());
        }
    }
}
