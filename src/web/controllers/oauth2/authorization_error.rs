use http::HeaderMap;
use identity_application::error::AppError;
use identity_domain::openid_connect::{OAuthErrorCode, OAuthErrorResponse};
use identity_infrastructure::{AppState, i18n::resolve_locale_from_headers};

use crate::controllers::response::error_message;

pub(super) fn oauth_error_response(
    ctx: &AppState,
    headers: &HeaderMap,
    code: OAuthErrorCode,
    source: Option<&AppError>,
) -> OAuthErrorResponse {
    let i18n = ctx.resources().i18n();
    let locale = resolve_locale_from_headers(headers);
    let description = match source {
        Some(error) => error_message(i18n, &locale, error),
        None => i18n.t(&locale, &format!("oauth-error-description-{code}")),
    };
    OAuthErrorResponse::new(code).with_description(description)
}

#[cfg(test)]
mod tests {
    use super::oauth_error_response;

    use http::{HeaderMap, HeaderValue, header};
    use identity_domain::openid_connect::OAuthErrorCode;

    #[tokio::test]
    async fn protocol_errors_use_the_same_localized_response_format() {
        let ctx = identity_infrastructure::test_app_state_with_mock_settings().await;
        let mut headers = HeaderMap::new();
        headers.insert(header::ACCEPT_LANGUAGE, HeaderValue::from_static("zh-CN"));

        for (code, expected) in [
            (OAuthErrorCode::LoginRequired, "需要登录后才能继续"),
            (OAuthErrorCode::AccessDenied, "授权请求已被拒绝"),
        ] {
            let response = oauth_error_response(&ctx, &headers, code, None);
            assert_eq!(response.error_description.as_deref(), Some(expected));
        }
    }
}
