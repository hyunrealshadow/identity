use std::time::Duration;

use async_trait::async_trait;
use http::HeaderMap;
use identity_application::{
    observability::outbound_trace,
    openid_connect::logout::{
        BackChannelLogoutDelivery, BackChannelLogoutNotification, BackChannelLogoutSender,
    },
};
use reqwest::{Client, Error};
use tracing::{Instrument as _, warn};

use super::remote::{build_pinned_client, resolve_and_validate_target};

const BACKCHANNEL_LOGOUT_TIMEOUT: Duration = Duration::from_secs(5);

pub struct HttpBackChannelLogoutSender {
    client: Client,
    allow_private_targets: bool,
    allow_invalid_certs: bool,
    allow_insecure_scheme: bool,
}

impl HttpBackChannelLogoutSender {
    pub fn new(allow_invalid_certs: bool, allow_private_targets: bool) -> Result<Self, Error> {
        let client = build_pinned_client(BACKCHANNEL_LOGOUT_TIMEOUT, allow_invalid_certs, None)?;
        Ok(Self {
            client,
            allow_private_targets,
            allow_invalid_certs,
            allow_insecure_scheme: false,
        })
    }

    #[cfg(any(test, feature = "test-support"))]
    pub fn for_test_local_http() -> Result<Self, Error> {
        let client = build_pinned_client(BACKCHANNEL_LOGOUT_TIMEOUT, false, None)?;
        Ok(Self {
            client,
            allow_private_targets: true,
            allow_invalid_certs: false,
            allow_insecure_scheme: true,
        })
    }
}

#[async_trait]
impl BackChannelLogoutSender for HttpBackChannelLogoutSender {
    async fn send(
        &self,
        notification: &BackChannelLogoutNotification,
    ) -> BackChannelLogoutDelivery {
        let pinned = match resolve_and_validate_target(
            &notification.logout_uri,
            self.allow_private_targets,
            self.allow_insecure_scheme,
        )
        .await
        {
            Ok(pinned) => pinned,
            Err(error) => {
                warn!(
                    client_id = %notification.client_id,
                    error = %error,
                    "back-channel logout target rejected by outbound URL policy"
                );
                return BackChannelLogoutDelivery::TransportFailed;
            }
        };

        let client_owner;
        let client = match pinned.as_ref() {
            Some((host, addrs)) => {
                match build_pinned_client(
                    BACKCHANNEL_LOGOUT_TIMEOUT,
                    self.allow_invalid_certs,
                    Some((host, addrs)),
                ) {
                    Ok(built) => {
                        client_owner = built;
                        &client_owner
                    }
                    Err(error) => {
                        warn!(
                            client_id = %notification.client_id,
                            error = %error,
                            "back-channel logout HTTP client build failed"
                        );
                        return BackChannelLogoutDelivery::TransportFailed;
                    }
                }
            }
            None => &self.client,
        };

        let trace = outbound_trace();
        let mut headers = HeaderMap::new();
        trace.inject(&notification.logout_uri, &mut headers);
        let span = trace.client_span("POST", &notification.logout_uri);
        let result = client
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
