use std::time::Duration;

use async_trait::async_trait;
use identity_application::openid_connect::logout::{
    BackChannelLogoutDelivery, BackChannelLogoutNotification, BackChannelLogoutSender,
};
use tracing::Instrument as _;

pub struct HttpBackChannelLogoutSender {
    client: reqwest::Client,
}

impl HttpBackChannelLogoutSender {
    pub fn new(allow_invalid_certs: bool) -> Result<Self, reqwest::Error> {
        let client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(Duration::from_secs(5))
            .danger_accept_invalid_certs(allow_invalid_certs)
            .build()?;
        Ok(Self { client })
    }
}

#[async_trait]
impl BackChannelLogoutSender for HttpBackChannelLogoutSender {
    async fn send(
        &self,
        notification: &BackChannelLogoutNotification,
    ) -> BackChannelLogoutDelivery {
        let trace = identity_application::observability::outbound_trace();
        let mut headers = http::HeaderMap::new();
        trace.inject(&notification.logout_uri, &mut headers);
        let span = trace.client_span("POST", &notification.logout_uri);
        let result = self
            .client
            .post(notification.logout_uri.clone())
            .headers(headers)
            .form(&[("logout_token", notification.logout_token.as_str())])
            .send()
            .instrument(span.clone())
            .await;

        match result {
            Ok(response) => {
                span.record("http.response.status_code", response.status().as_u16());
                if response.status().is_success() {
                    BackChannelLogoutDelivery::Delivered
                } else {
                    tracing::warn!(
                        client_id = %notification.client_id,
                        status = %response.status(),
                        "back-channel logout request returned non-success status"
                    );
                    BackChannelLogoutDelivery::Rejected
                }
            }
            Err(error) => {
                tracing::warn!(
                    client_id = %notification.client_id,
                    error = %error,
                    "back-channel logout request failed"
                );
                BackChannelLogoutDelivery::TransportFailed
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use url::Url;
    use uuid::Uuid;

    #[tokio::test]
    async fn posts_logout_token_as_form_and_reports_response_status() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = Vec::new();
            loop {
                let mut chunk = [0_u8; 1024];
                let read = stream.read(&mut chunk).await.unwrap();
                assert!(read > 0);
                request.extend_from_slice(&chunk[..read]);
                if let Some(header_end) = request.windows(4).position(|bytes| bytes == b"\r\n\r\n")
                {
                    let header_end = header_end + 4;
                    let headers = String::from_utf8_lossy(&request[..header_end]);
                    let content_length = headers
                        .lines()
                        .find_map(|line| {
                            line.split_once(':').and_then(|(name, value)| {
                                name.eq_ignore_ascii_case("content-length")
                                    .then(|| value.trim().parse::<usize>().unwrap())
                            })
                        })
                        .unwrap();
                    if request.len() >= header_end + content_length {
                        break;
                    }
                }
            }
            stream
                .write_all(b"HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\n\r\n")
                .await
                .unwrap();
            String::from_utf8(request).unwrap()
        });

        let sender = HttpBackChannelLogoutSender::new(false).unwrap();
        let notification = BackChannelLogoutNotification {
            client_id: Uuid::new_v4(),
            logout_uri: Url::parse(&format!("http://{address}/backchannel_logout")).unwrap(),
            logout_token: "signed.token.value".to_owned(),
        };
        let result = sender.send(&notification).await;
        let request = server.await.unwrap();

        assert_eq!(result, BackChannelLogoutDelivery::Rejected);
        assert!(request.starts_with("POST /backchannel_logout HTTP/1.1\r\n"));
        assert!(
            request
                .to_ascii_lowercase()
                .contains("content-type: application/x-www-form-urlencoded")
        );
        assert!(request.ends_with("logout_token=signed.token.value"));
    }
}
