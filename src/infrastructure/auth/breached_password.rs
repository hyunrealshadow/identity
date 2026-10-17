//! Pwned Passwords range API: only five SHA-1 hex characters leave the process.
use async_trait::async_trait;
use identity_application::{
    auth::password_policy::BreachedPasswordChecker,
    error::{AppError, codes::auth::AuthErrorCode},
};
use reqwest::{Client, Url};
use std::time::Duration;
use tokio::sync::Semaphore;

pub struct PwnedPasswordChecker {
    client: Client,
    endpoint: Url,
    requests: Semaphore,
}

impl PwnedPasswordChecker {
    pub fn new() -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let endpoint = Url::parse(
            &std::env::var("IDENTITY_PWNED_PASSWORDS_URL")
                .unwrap_or_else(|_| "https://api.pwnedpasswords.com/range/".to_owned()),
        )?;
        if endpoint.scheme() != "https"
            || !endpoint.path().ends_with('/')
            || !endpoint.username().is_empty()
            || endpoint.password().is_some()
            || endpoint.query().is_some()
            || endpoint.fragment().is_some()
        {
            return Err(std::io::Error::other("IDENTITY_PWNED_PASSWORDS_URL must be an HTTPS base URL ending in / without credentials, query or fragment").into());
        }
        Ok(Self {
            client: Client::builder()
                .https_only(true)
                .redirect(reqwest::redirect::Policy::none())
                .timeout(Duration::from_secs(3))
                .connect_timeout(Duration::from_secs(2))
                .user_agent("Identity-Password-Policy")
                .build()?,
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
        let digest = openssl::sha::sha1(password.as_bytes());
        let hash: String = digest.iter().map(|byte| format!("{byte:02X}")).collect();
        let url = self.endpoint.join(&hash[..5]).map_err(|_| unavailable())?;
        let mut response = self
            .client
            .get(url)
            .header("Add-Padding", "true")
            .send()
            .await
            .map_err(|_| unavailable())?;
        if response.status() != reqwest::StatusCode::OK {
            return Err(unavailable());
        }
        let mut body = Vec::new();
        while let Some(chunk) = response.chunk().await.map_err(|_| unavailable())? {
            if body.len() + chunk.len() > 2 * 1024 * 1024 {
                return Err(unavailable());
            }
            body.extend_from_slice(&chunk);
        }
        let body = std::str::from_utf8(&body).map_err(|_| unavailable())?;
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
    #[tokio::test]
    async fn sends_only_the_range_prefix_and_fails_closed_on_http_errors() {
        use std::io::{Read, Write};
        let password = "a unique password for transport test";
        let hash: String = openssl::sha::sha1(password.as_bytes())
            .iter()
            .map(|b| format!("{b:02X}"))
            .collect();
        for status in [200, 503] {
            let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            let address = listener.local_addr().unwrap();
            let expected = hash.clone();
            let server = std::thread::spawn(move || {
                let (mut socket, _) = listener.accept().unwrap();
                socket
                    .set_read_timeout(Some(Duration::from_secs(3)))
                    .unwrap();
                let mut request = Vec::new();
                while !request.ends_with(b"\r\n\r\n") {
                    let mut byte = [0];
                    assert_eq!(socket.read(&mut byte).unwrap(), 1);
                    request.push(byte[0]);
                }
                let request = String::from_utf8(request).unwrap();
                assert!(request.starts_with(&format!("GET /range/{} HTTP/1.1", &expected[..5])));
                assert!(request.to_lowercase().contains("add-padding: true"));
                assert!(!request.contains(password));
                assert!(!request.contains(&expected[5..]));
                let body = format!("{}:1\r\n", &expected[5..]);
                write!(socket, "HTTP/1.1 {status} test\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len()).unwrap();
            });
            let checker = PwnedPasswordChecker {
                client: Client::builder()
                    .no_proxy()
                    .timeout(Duration::from_secs(3))
                    .build()
                    .unwrap(),
                endpoint: Url::parse(&format!("http://{address}/range/")).unwrap(),
                requests: Semaphore::new(1),
            };
            let result = checker.is_breached(password).await;
            if status == 200 {
                assert!(result.unwrap());
            } else {
                assert!(result.is_err());
            }
            server.join().unwrap();
        }
    }
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
