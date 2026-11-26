//! SMTP delivery with password or XOAUTH2 authentication.
//!
//! Each message opens its own connection with the settings it is given, so a
//! settings change applies to the next message. XOAUTH2 access tokens are
//! cached until shortly before they expire.

use std::{
    collections::HashMap,
    sync::Arc,
    time::{Duration, Instant},
};

use async_trait::async_trait;
use identity_application::{
    data_protection::DataProtector,
    email::{EMAIL_DELIVERY_SECRET_PURPOSE, EmailDeliveryError, EmailMessage, EmailSender},
    setting::{
        EmailDeliverySettings, ProtectedSecret, SmtpAuthentication, SmtpSecurity, Xoauth2Grant,
        Xoauth2Settings,
    },
};
use lettre::{
    AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor,
    message::{Mailbox, MultiPart},
    transport::smtp::{
        AsyncSmtpTransportBuilder,
        authentication::{Credentials, Mechanism},
    },
};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use tokio::sync::Mutex;
use tracing::Instrument;

const SMTP_TIMEOUT: Duration = Duration::from_secs(20);
const TOKEN_TIMEOUT: Duration = Duration::from_secs(10);
/// Renew a cached access token this long before it expires.
const TOKEN_EXPIRY_MARGIN: Duration = Duration::from_secs(60);
const DEFAULT_TOKEN_LIFETIME: Duration = Duration::from_secs(300);
const MAX_DETAIL_LENGTH: usize = 300;

pub struct SmtpEmailSender {
    protector: Arc<dyn DataProtector>,
    http: reqwest::Client,
    tokens: Mutex<HashMap<[u8; 32], CachedToken>>,
}

struct CachedToken {
    access_token: String,
    renew_at: Instant,
}

#[derive(Deserialize)]
struct TokenResponse {
    access_token: String,
    expires_in: Option<u64>,
}

#[derive(Deserialize)]
struct TokenErrorResponse {
    error: String,
    error_description: Option<String>,
}

/// Line width of the plain-text alternative.
const PLAIN_TEXT_WIDTH: usize = 78;

/// The plain-text alternative of an HTML body, for clients that do not show
/// HTML. Links are kept as numbered references below the text.
fn plain_text(html: &str) -> String {
    html2text::config::plain_no_decorate()
        .link_footnotes(true)
        .no_link_wrapping()
        .string_from_read(html.as_bytes(), PLAIN_TEXT_WIDTH)
        .unwrap_or_default()
}

fn truncate(text: &str) -> String {
    let text = text.trim();
    let mut out: String = text.chars().take(MAX_DETAIL_LENGTH).collect();
    if text.chars().count() > MAX_DETAIL_LENGTH {
        out.push('…');
    }
    out
}

impl SmtpEmailSender {
    pub fn new(protector: Arc<dyn DataProtector>) -> Result<Self, reqwest::Error> {
        Ok(Self {
            protector,
            http: reqwest::Client::builder()
                .timeout(TOKEN_TIMEOUT)
                .redirect(reqwest::redirect::Policy::none())
                .build()?,
            tokens: Mutex::new(HashMap::new()),
        })
    }

    async fn reveal(&self, secret: &ProtectedSecret) -> Result<String, EmailDeliveryError> {
        let bytes = self
            .protector
            .unprotect(EMAIL_DELIVERY_SECRET_PURPOSE, secret.protected())
            .await
            .map_err(|_| EmailDeliveryError::SecretUnavailable)?;
        String::from_utf8(bytes).map_err(|_| EmailDeliveryError::SecretUnavailable)
    }

    async fn credentials(
        &self,
        authentication: &SmtpAuthentication,
    ) -> Result<Option<(Credentials, Vec<Mechanism>, Option<[u8; 32]>)>, EmailDeliveryError> {
        match authentication {
            SmtpAuthentication::None => Ok(None),
            SmtpAuthentication::Password { username, password } => Ok(Some((
                Credentials::new(username.clone(), self.reveal(password).await?),
                vec![Mechanism::Plain, Mechanism::Login],
                None,
            ))),
            SmtpAuthentication::Xoauth2(oauth) => {
                let (token, key, from_cache) = self.access_token(oauth).await?;
                Ok(Some((
                    Credentials::new(oauth.username.clone(), token),
                    vec![Mechanism::Xoauth2],
                    from_cache.then_some(key),
                )))
            }
        }
    }

    /// An access token for `oauth`, from the cache or the token endpoint.
    /// Returns `(token, cache_key, from_cache)` without holding the cache
    /// mutex across the HTTP request.
    async fn access_token(
        &self,
        oauth: &Xoauth2Settings,
    ) -> Result<(String, [u8; 32], bool), EmailDeliveryError> {
        // Keyed by everything that selects the token, including the
        // protected secrets, so replacing one is never answered from the cache.
        let key: [u8; 32] = Sha256::digest(serde_json::to_vec(oauth).unwrap_or_default()).into();
        {
            let tokens = self.tokens.lock().await;
            if let Some(cached) = tokens.get(&key)
                && cached.renew_at > Instant::now()
            {
                return Ok((cached.access_token.clone(), key, true));
            }
        }
        let span = tracing::info_span!("email.xoauth2.token", http.request.method = "POST");
        let fetched = self.fetch_token(oauth).instrument(span).await?;
        let renew_at = Instant::now()
            + fetched
                .expires_in
                .map_or(DEFAULT_TOKEN_LIFETIME, Duration::from_secs)
                .saturating_sub(TOKEN_EXPIRY_MARGIN);
        let mut tokens = self.tokens.lock().await;
        tokens.retain(|_, cached| cached.renew_at > Instant::now());
        tokens.insert(
            key,
            CachedToken {
                access_token: fetched.access_token.clone(),
                renew_at,
            },
        );
        Ok((fetched.access_token, key, false))
    }

    async fn evict_token(&self, key: &[u8; 32]) {
        self.tokens.lock().await.remove(key);
    }

    async fn fetch_token(
        &self,
        oauth: &Xoauth2Settings,
    ) -> Result<TokenResponse, EmailDeliveryError> {
        let mut form: Vec<(&str, String)> = vec![("client_id", oauth.client_id.clone())];
        match oauth.grant {
            Xoauth2Grant::RefreshToken => {
                let refresh_token = oauth
                    .refresh_token
                    .as_ref()
                    .ok_or(EmailDeliveryError::SecretUnavailable)?;
                form.push(("grant_type", "refresh_token".to_owned()));
                form.push(("refresh_token", self.reveal(refresh_token).await?));
            }
            Xoauth2Grant::ClientCredentials => {
                form.push(("grant_type", "client_credentials".to_owned()));
            }
        }
        if let Some(secret) = &oauth.client_secret {
            form.push(("client_secret", self.reveal(secret).await?));
        }
        if let Some(scope) = &oauth.scope {
            form.push(("scope", scope.clone()));
        }
        let mut response = self
            .http
            .post(&oauth.token_endpoint)
            .header(reqwest::header::ACCEPT, "application/json")
            .form(&form)
            .send()
            .await
            .map_err(|error| EmailDeliveryError::Transport {
                detail: truncate(&format!(
                    "token endpoint unreachable: {}",
                    error.without_url()
                )),
            })?;
        const MAX_OAUTH_TOKEN_RESPONSE_BYTES: usize = 64 * 1024;
        let status = response.status();
        if response
            .content_length()
            .is_some_and(|length| length > MAX_OAUTH_TOKEN_RESPONSE_BYTES as u64)
        {
            return Err(EmailDeliveryError::Transport {
                detail: "token endpoint response too large".to_owned(),
            });
        }
        let mut body = Vec::new();
        while let Some(chunk) =
            response
                .chunk()
                .await
                .map_err(|error| EmailDeliveryError::Transport {
                    detail: truncate(&error.without_url().to_string()),
                })?
        {
            if body.len() + chunk.len() > MAX_OAUTH_TOKEN_RESPONSE_BYTES {
                return Err(EmailDeliveryError::Transport {
                    detail: "token endpoint response too large".to_owned(),
                });
            }
            body.extend_from_slice(&chunk);
        }
        if !status.is_success() {
            let detail = serde_json::from_slice::<TokenErrorResponse>(&body).map_or_else(
                |_| format!("token endpoint answered {status}"),
                |error| match error.error_description {
                    Some(description) => format!("{}: {description}", error.error),
                    None => error.error,
                },
            );
            return Err(classify_token_status(status, truncate(&detail)));
        }
        serde_json::from_slice::<TokenResponse>(&body).map_err(|_| {
            EmailDeliveryError::Authentication {
                detail: "token endpoint returned no access token".to_owned(),
            }
        })
    }

    fn transport(
        settings: &EmailDeliverySettings,
    ) -> Result<AsyncSmtpTransportBuilder, EmailDeliveryError> {
        let host = settings.host.trim();
        let builder = match settings.security {
            SmtpSecurity::Tls => AsyncSmtpTransport::<Tokio1Executor>::relay(host),
            SmtpSecurity::StartTls => AsyncSmtpTransport::<Tokio1Executor>::starttls_relay(host),
            SmtpSecurity::None => Ok(AsyncSmtpTransport::<Tokio1Executor>::builder_dangerous(
                host,
            )),
        }
        .map_err(|error| EmailDeliveryError::Transport {
            detail: truncate(&error.to_string()),
        })?;
        Ok(builder.port(settings.port).timeout(Some(SMTP_TIMEOUT)))
    }
}

fn is_auth_failure_code(code: &str) -> bool {
    matches!(code, "530" | "534" | "535" | "538")
}

fn classify_token_status(status: reqwest::StatusCode, detail: String) -> EmailDeliveryError {
    if status == reqwest::StatusCode::TOO_MANY_REQUESTS || status.is_server_error() {
        EmailDeliveryError::Transport { detail }
    } else {
        EmailDeliveryError::Authentication { detail }
    }
}

fn classify_smtp_error(error: &lettre::transport::smtp::Error) -> EmailDeliveryError {
    let detail = truncate(&error.to_string());
    if error
        .status()
        .is_some_and(|code| is_auth_failure_code(&code.to_string()))
    {
        EmailDeliveryError::Authentication { detail }
    } else if error.is_permanent() {
        // Another attempt would be refused the same way.
        EmailDeliveryError::Rejected { detail }
    } else {
        EmailDeliveryError::Transport { detail }
    }
}

fn build_email(
    settings: &EmailDeliverySettings,
    message: &EmailMessage,
) -> Result<Message, EmailDeliveryError> {
    Message::builder()
        .from(mailbox(
            settings.sender_name.as_deref(),
            &settings.sender_address,
        )?)
        .to(mailbox(message.to_name.as_deref(), &message.to_address)?)
        .subject(message.subject.clone())
        .multipart(MultiPart::alternative_plain_html(
            plain_text(&message.html),
            message.html.clone(),
        ))
        .map_err(|error| EmailDeliveryError::Rejected {
            detail: truncate(&error.to_string()),
        })
}

fn mailbox(name: Option<&str>, address: &str) -> Result<Mailbox, EmailDeliveryError> {
    Ok(Mailbox::new(
        name.map(str::to_owned),
        address
            .trim()
            .parse()
            .map_err(|_| EmailDeliveryError::InvalidAddress)?,
    ))
}

#[async_trait]
impl EmailSender for SmtpEmailSender {
    async fn send(
        &self,
        settings: &EmailDeliverySettings,
        message: EmailMessage,
    ) -> Result<(), EmailDeliveryError> {
        let span = tracing::info_span!(
            "email.send",
            server.address = %settings.host,
            server.port = settings.port,
            email.security = ?settings.security,
        );
        async move {
            if !settings.is_configured() {
                return Err(EmailDeliveryError::NotConfigured);
            }
            let email = build_email(settings, &message)?;
            let mut transport = Self::transport(settings)?;
            let cached_key = if let Some((credentials, mechanisms, cached_key)) =
                self.credentials(&settings.authentication).await?
            {
                transport = transport
                    .credentials(credentials)
                    .authentication(mechanisms);
                cached_key
            } else {
                None
            };
            match transport.build().send(email).await {
                Ok(_) => Ok(()),
                Err(error) => {
                    if let Some(key) = cached_key
                        && error.status().is_some_and(|code| code.to_string() == "535")
                    {
                        // Cached XOAUTH2 token may have been revoked early; drop it
                        // and retry once with a freshly fetched token.
                        self.evict_token(&key).await;
                        let email = build_email(settings, &message)?;
                        let mut transport = Self::transport(settings)?;
                        if let Some((credentials, mechanisms, _)) =
                            self.credentials(&settings.authentication).await?
                        {
                            transport = transport
                                .credentials(credentials)
                                .authentication(mechanisms);
                        }
                        return transport
                            .build()
                            .send(email)
                            .await
                            .map(drop)
                            .map_err(|retry_error| classify_smtp_error(&retry_error));
                    }
                    Err(classify_smtp_error(&error))
                }
            }
        }
        .instrument(span)
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_plain_text_alternative_keeps_text_and_links() {
        let link = "https://login.example.com/login/email?login_id=a&token=b";
        let text = plain_text(&format!(
            "<!doctype html><html><head><style>p {{ color: red }}</style></head>\
             <body><p>Your code is <strong>246810</strong></p>\
             <p><a href=\"{}\">Sign in</a></p></body></html>",
            link.replace('&', "&amp;")
        ));
        assert!(text.contains("Your code is 246810"), "{text}");
        assert!(text.contains(link), "{text}");
        assert!(!text.contains("color"));
    }

    #[test]
    fn transient_token_endpoint_statuses_are_retried_while_client_errors_are_auth_failures() {
        assert!(matches!(
            classify_token_status(reqwest::StatusCode::TOO_MANY_REQUESTS, "rate".to_owned()),
            EmailDeliveryError::Transport { .. }
        ));
        assert!(matches!(
            classify_token_status(
                reqwest::StatusCode::SERVICE_UNAVAILABLE,
                "unavailable".to_owned()
            ),
            EmailDeliveryError::Transport { .. }
        ));
        assert!(matches!(
            classify_token_status(reqwest::StatusCode::BAD_REQUEST, "invalid_grant".to_owned()),
            EmailDeliveryError::Authentication { .. }
        ));
        assert!(matches!(
            classify_token_status(reqwest::StatusCode::UNAUTHORIZED, "unauthorized".to_owned()),
            EmailDeliveryError::Authentication { .. }
        ));
        assert!(is_auth_failure_code("530"));
        assert!(is_auth_failure_code("534"));
        assert!(is_auth_failure_code("535"));
        assert!(is_auth_failure_code("538"));
        assert!(!is_auth_failure_code("550"));
    }
}
