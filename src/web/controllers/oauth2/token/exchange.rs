use http::StatusCode;
use identity_application::{
    error::{AppError, codes::token::TokenErrorCode},
    openid_connect::token::{
        AuthorizationCodeGrantParams, ClientCredentialsGrantParams, DeviceCodeGrantParams,
        RefreshTokenGrantParams,
    },
};
use identity_domain::openid_connect::GrantType;
use salvo::{Depot, Request, handler, handler::HoopedHandler};

use super::{
    super::{
        client_credentials::ClientCredentials,
        pipeline::{Endpoint, Extract, RequireState, take},
    },
    error::TokenWebError,
    request::TokenForm,
};
use crate::controllers::response::{
    AppResponse, app_state, insert_no_store_headers, json_response,
};

#[cfg(test)]
use super::super::error::Rfc6749Error;
#[cfg(test)]
use super::error::token_error_response;
#[cfg(test)]
use crate::infrastructure::i18n::resolve_locale_from_headers;

enum PreparedGrant {
    AuthorizationCode(AuthorizationCodeGrantParams),
    DeviceCode(DeviceCodeGrantParams),
    RefreshToken(RefreshTokenGrantParams),
    ClientCredentials(ClientCredentialsGrantParams),
}

pub fn endpoint() -> HoopedHandler {
    Endpoint::new("token")
        .action("state", RequireState::<TokenWebError>::new())
        .action("parse_form", Extract::<TokenForm, TokenWebError>::form())
        .action("prepare_grant", prepare_grant)
        .finish("exchange", token)
}

#[handler]
async fn prepare_grant(depot: &mut Depot, req: &mut Request) -> Result<(), TokenWebError> {
    let form: TokenForm = take(depot)?;
    let credentials = ClientCredentials::resolve(
        req.headers(),
        form.client_id,
        form.client_secret,
        form.client_assertion_type,
    )?;
    let grant = match form.grant_type.parse::<GrantType>() {
        Ok(GrantType::AuthorizationCode) => {
            PreparedGrant::AuthorizationCode(AuthorizationCodeGrantParams {
                resources: form.resources,
                code: form.code.unwrap_or_default(),
                redirect_uri: form.redirect_uri,
                client_id: credentials.client_id,
                client_secret: credentials.client_secret,
                client_secret_basic: credentials.basic,
                client_assertion_type: credentials.assertion_type,
                client_assertion: form.client_assertion,
                code_verifier: form.code_verifier,
            })
        }
        Ok(GrantType::DeviceCode) => PreparedGrant::DeviceCode(DeviceCodeGrantParams {
            resources: form.resources,
            device_code: form.device_code.unwrap_or_default(),
            client_id: credentials.client_id,
            client_secret: credentials.client_secret,
            client_secret_basic: credentials.basic,
            client_assertion_type: credentials.assertion_type,
            client_assertion: form.client_assertion,
        }),
        Ok(GrantType::RefreshToken) => PreparedGrant::RefreshToken(RefreshTokenGrantParams {
            resources: form.resources,
            refresh_token: form.refresh_token.unwrap_or_default(),
            scope: form.scope,
            client_id: credentials.client_id,
            client_secret: credentials.client_secret,
            client_secret_basic: credentials.basic,
            client_assertion_type: credentials.assertion_type,
            client_assertion: form.client_assertion,
        }),
        Ok(GrantType::ClientCredentials) => {
            PreparedGrant::ClientCredentials(ClientCredentialsGrantParams {
                resources: form.resources,
                scope: form.scope,
                client_id: credentials.client_id,
                client_secret: credentials.client_secret,
                client_secret_basic: credentials.basic,
                client_assertion_type: credentials.assertion_type,
                client_assertion: form.client_assertion,
            })
        }
        _ => {
            return Err(AppError::from_code(TokenErrorCode::UnsupportedGrantType)
                .with_param("grant_type", form.grant_type)
                .into());
        }
    };

    depot.insert_typed(grant);
    Ok(())
}

#[handler]
async fn token(depot: &mut Depot) -> Result<AppResponse, TokenWebError> {
    let ctx = app_state(depot)?;
    let grant: PreparedGrant = take(depot)?;
    let service = ctx.services().oidc_token();
    let response = match grant {
        PreparedGrant::AuthorizationCode(params) => {
            service.exchange_authorization_code(params).await
        }
        PreparedGrant::DeviceCode(params) => service.exchange_device_code(params).await,
        PreparedGrant::RefreshToken(params) => service.exchange_refresh_token(params).await,
        PreparedGrant::ClientCredentials(params) => {
            service.exchange_client_credentials(params).await
        }
    }?;
    let mut response = json_response(StatusCode::OK, response);
    insert_no_store_headers(&mut response);
    Ok(AppResponse(response))
}

#[cfg(test)]
mod tests {
    use http::{
        HeaderMap, StatusCode, header,
        header::{AUTHORIZATION, CONTENT_TYPE},
    };
    use identity_application::error::codes::common::CommonErrorCode;
    use identity_infrastructure::test_app_state_with_mock_settings;
    use salvo::{
        Service,
        affix_state::inject,
        test::{ResponseExt, TestClient},
    };
    use serde_json::{Value, from_str};

    use super::super::super::client_credentials::parse_basic_client_auth;
    use crate::controllers::{oauth2::routes, response::parse_form};

    use super::*;

    #[tokio::test]
    async fn refresh_revocation_errors_respect_chinese_request_language() {
        let ctx = test_app_state_with_mock_settings().await;
        let mut headers = HeaderMap::new();
        headers.insert(header::ACCEPT_LANGUAGE, "zh-CN,zh;q=0.9".parse().unwrap());
        let locale = resolve_locale_from_headers(&headers);
        let mut response = token_error_response(
            AppError::from_code(TokenErrorCode::RevokeRefreshFailed),
            ctx.resources().i18n(),
            &locale,
        );
        assert_eq!(
            response.status_code,
            Some(StatusCode::INTERNAL_SERVER_ERROR)
        );
        let body = response.take_string().await.unwrap();
        let body: Value = from_str(&body).unwrap();
        assert_eq!(body["error"], "server_error");
        assert_eq!(body["error_description"], "撤销刷新令牌时发生意外错误");
    }

    #[test]
    fn rfc6749_status_for_invalid_grant_is_bad_request() {
        let error = TokenWebError(AppError::from_code(TokenErrorCode::RefreshTokenInvalid));
        assert_eq!(error.rfc6749_status(), StatusCode::BAD_REQUEST);
    }

    #[test]
    fn rfc6749_status_for_invalid_client_is_unauthorized() {
        let error = TokenWebError(AppError::from_code(TokenErrorCode::ClientAuthRequired));
        assert_eq!(error.rfc6749_status(), StatusCode::UNAUTHORIZED);
    }

    #[test]
    fn rfc6749_error_code_maps_refresh_errors_to_invalid_grant() {
        let error = TokenWebError(AppError::from_code(TokenErrorCode::RefreshTokenInvalid));
        assert_eq!(error.rfc6749_error_code(), "invalid_grant");
    }

    #[test]
    fn rfc6749_error_code_maps_grant_permission_to_unauthorized_client() {
        let error = TokenWebError(AppError::from_code(TokenErrorCode::ClientGrantNotAllowed));

        assert_eq!(error.rfc6749_error_code(), "unauthorized_client");
        assert_eq!(error.rfc6749_status(), StatusCode::BAD_REQUEST);
    }

    #[test]
    fn client_credentials_scope_error_maps_to_invalid_scope() {
        let error = TokenWebError(AppError::from_code(
            TokenErrorCode::ClientCredentialsScopeNotAllowed,
        ));
        assert_eq!(error.rfc6749_error_code(), "invalid_scope");
    }

    #[test]
    fn rfc6749_error_code_maps_device_grant_errors() {
        let cases = [
            (TokenErrorCode::DeviceCodePending, "authorization_pending"),
            (TokenErrorCode::DeviceCodeSlowDown, "slow_down"),
            (TokenErrorCode::DeviceCodeDenied, "access_denied"),
            (TokenErrorCode::DeviceCodeRevoked, "access_denied"),
            (TokenErrorCode::DeviceCodeExpired, "expired_token"),
            (TokenErrorCode::DeviceCodeNotFound, "invalid_grant"),
            (TokenErrorCode::DeviceCodeClientMismatch, "invalid_grant"),
            (TokenErrorCode::DeviceCodeUserNotFound, "invalid_grant"),
        ];

        for (code, expected) in cases {
            let error = TokenWebError(AppError::from_code(code));
            assert_eq!(error.rfc6749_error_code(), expected, "{code:?}");
            assert_eq!(error.rfc6749_status(), StatusCode::BAD_REQUEST, "{code:?}");
        }

        let internal = TokenWebError(AppError::from_code(TokenErrorCode::DeviceRedemptionFailed));
        assert_eq!(internal.rfc6749_error_code(), "server_error");
        assert_eq!(internal.rfc6749_status(), StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[tokio::test]
    async fn token_route_dispatches_the_device_code_grant() {
        let app = routes().hoop(inject(test_app_state_with_mock_settings().await));
        let service = Service::new(app);
        let mut response = TestClient::post("http://127.0.0.1:5800/oauth2/token")
            .add_header(CONTENT_TYPE, "application/x-www-form-urlencoded", true)
            .body("grant_type=urn:ietf:params:oauth:grant-type:device_code&device_code=unknown")
            .send(&service)
            .await;

        assert_eq!(response.status_code, Some(StatusCode::BAD_REQUEST));
        let body = response.take_string().await.unwrap();
        assert!(body.contains("invalid_request"), "{body}");
    }

    #[test]
    fn rfc6749_error_code_keeps_unsupported_grant_type_distinct() {
        let error = TokenWebError(AppError::from_code(TokenErrorCode::UnsupportedGrantType));

        assert_eq!(error.rfc6749_error_code(), "unsupported_grant_type");
    }

    #[test]
    fn detailed_authorization_code_errors_map_to_invalid_grant() {
        for code in [
            TokenErrorCode::AuthCodeRevoked,
            TokenErrorCode::AuthCodeExpired,
            TokenErrorCode::AuthCodeSessionNotFound,
            TokenErrorCode::AuthCodeSessionInactive,
            TokenErrorCode::AuthCodeSessionRevoked,
            TokenErrorCode::AuthCodeSessionExpired,
            TokenErrorCode::AuthCodeSessionUserMismatch,
            TokenErrorCode::AuthCodeClaimFailed,
        ] {
            let error = TokenWebError(AppError::from_code(code));
            assert_eq!(error.rfc6749_error_code(), "invalid_grant", "{code:?}");
            assert_eq!(error.rfc6749_status(), StatusCode::BAD_REQUEST);
        }
        let error = TokenWebError(AppError::from_code(
            TokenErrorCode::AuthCodeSessionLookupFailed,
        ));
        assert_eq!(error.rfc6749_error_code(), "server_error");
        assert_eq!(error.rfc6749_status(), StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[test]
    fn parse_basic_client_auth_reads_client_credentials() {
        let mut headers = HeaderMap::new();
        headers.insert(
            AUTHORIZATION,
            "Basic MDAwMDAwMDAtMDAwMC0wMDAwLTAwMDAtMDAwMDAwMDAwMDAwOnNlY3JldC0xMjM="
                .parse()
                .unwrap(),
        );

        let parsed = parse_basic_client_auth(&headers).unwrap();
        assert_eq!(parsed.0, "00000000-0000-0000-0000-000000000000");
        assert_eq!(parsed.1, "secret-123");
    }

    #[tokio::test]
    async fn token_form_retains_repeated_resources_and_empty_targets() {
        for (body, expected) in [
            (
                "grant_type=client_credentials&resource=https%3A%2F%2Fa.example%2F&resource=urn%3Ab",
                vec!["https://a.example/", "urn:b"],
            ),
            ("grant_type=client_credentials&resource=", vec![""]),
            ("grant_type=client_credentials", vec![]),
        ] {
            let mut req = TestClient::post("http://localhost/oauth2/token")
                .add_header(
                    header::CONTENT_TYPE,
                    "application/x-www-form-urlencoded",
                    true,
                )
                .text(body)
                .build();
            let form: TokenForm = parse_form(&mut req).await.unwrap();
            assert_eq!(form.resources, expected);
        }
        let error = TokenWebError(AppError::from_code(CommonErrorCode::InvalidTarget));
        assert_eq!(error.rfc6749_error_code(), "invalid_target");
        assert_eq!(error.rfc6749_status(), StatusCode::BAD_REQUEST);
    }
}
