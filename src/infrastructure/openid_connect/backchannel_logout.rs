use std::time::Duration;

use async_trait::async_trait;
use http::HeaderMap;
use identity_application::{
    observability::outbound_trace,
    openid_connect::logout::{
        BackChannelLogoutDelivery, BackChannelLogoutNotification, BackChannelLogoutSender,
    },
};
use reqwest::{Client, Error, redirect::Policy};
use tracing::{Instrument as _, warn};

pub struct HttpBackChannelLogoutSender {
    client: Client,
}

impl HttpBackChannelLogoutSender {
    pub fn new(allow_invalid_certs: bool) -> Result<Self, Error> {
        let client = Client::builder()
            .redirect(Policy::none())
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
        let trace = outbound_trace();
        let mut headers = HeaderMap::new();
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
                    warn!(
                        client_id = %notification.client_id,
                        status = %response.status(),
                        "back-channel logout request returned non-success status"
                    );
                    BackChannelLogoutDelivery::Rejected
                }
            }
            Err(error) => {
                warn!(
                    client_id = %notification.client_id,
                    error = %error,
                    "back-channel logout request failed"
                );
                BackChannelLogoutDelivery::TransportFailed
            }
        }
    }
}
