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
    ) -> Result<Option<(Credentials, Vec<Mechanism>)>, EmailDeliveryError> {
        match authentication {
            SmtpAuthentication::None => Ok(None),
            SmtpAuthentication::Password { username, password } => Ok(Some((
                Credentials::new(username.clone(), self.reveal(password).await?),
                vec![Mechanism::Plain, Mechanism::Login],
            ))),
            SmtpAuthentication::Xoauth2(oauth) => Ok(Some((
                Credentials::new(oauth.username.clone(), self.access_token(oauth).await?),
                vec![Mechanism::Xoauth2],
            ))),
        }
    }

    /// An access token for `oauth`, from the cache or the token endpoint.
    async fn access_token(&self, oauth: &Xoauth2Settings) -> Result<String, EmailDeliveryError> {
        // Keyed by everything that selects the token, including the
        // protected secrets, so replacing one is never answered from the cache.
        let key: [u8; 32] = Sha256::digest(serde_json::to_vec(oauth).unwrap_or_default()).into();
        let mut tokens = self.tokens.lock().await;
        if let Some(cached) = tokens.get(&key)
            && cached.renew_at > Instant::now()
        {
            return Ok(cached.access_token.clone());
        }
        let span = tracing::info_span!("email.xoauth2.token", http.request.method = "POST");
        let fetched = self.fetch_token(oauth).instrument(span).await?;
        tokens.retain(|_, cached| cached.renew_at > Instant::now());
        tokens.insert(
            key,
            CachedToken {
                access_token: fetched.access_token.clone(),
                renew_at: Instant::now()
                    + fetched
                        .expires_in
                        .map_or(DEFAULT_TOKEN_LIFETIME, Duration::from_secs)
                        .saturating_sub(TOKEN_EXPIRY_MARGIN),
            },
        );
        Ok(fetched.access_token)
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
        let response = self
            .http
            .post(&oauth.token_endpoint)
            .header(reqwest::header::ACCEPT, "application/json")
            .form(&form)
            .send()
            .await
            .map_err(|error| EmailDeliveryError::Authentication {
                detail: truncate(&format!(
                    "token endpoint unreachable: {}",
                    error.without_url()
                )),
            })?;
        let status = response.status();
        let body = response
            .bytes()
            .await
            .map_err(|error| EmailDeliveryError::Authentication {
                detail: truncate(&error.without_url().to_string()),
            })?;
        if !status.is_success() {
            let detail = serde_json::from_slice::<TokenErrorResponse>(&body).map_or_else(
                |_| format!("token endpoint answered {status}"),
                |error| match error.error_description {
                    Some(description) => format!("{}: {description}", error.error),
                    None => error.error,
                },
            );
            return Err(EmailDeliveryError::Authentication {
                detail: truncate(&detail),
            });
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
            let email = Message::builder()
                .from(mailbox(
                    settings.sender_name.as_deref(),
                    &settings.sender_address,
                )?)
                .to(mailbox(message.to_name.as_deref(), &message.to_address)?)
                .subject(message.subject)
                .multipart(MultiPart::alternative_plain_html(
                    message.text,
                    message.html,
                ))
                .map_err(|error| EmailDeliveryError::Transport {
                    detail: truncate(&error.to_string()),
                })?;
            let mut transport = Self::transport(settings)?;
            if let Some((credentials, mechanisms)) =
                self.credentials(&settings.authentication).await?
            {
                transport = transport
                    .credentials(credentials)
                    .authentication(mechanisms);
            }
            transport
                .build()
                .send(email)
                .await
                .map(drop)
                .map_err(|error| {
                    let detail = truncate(&error.to_string());
                    // 535: authentication credentials invalid.
                    if error
                        .status()
                        .is_some_and(|code| code.to_string().starts_with("535"))
                    {
                        EmailDeliveryError::Authentication { detail }
                    } else {
                        EmailDeliveryError::Transport { detail }
                    }
                })
        }
        .instrument(span)
        .await
    }
}
