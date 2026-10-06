use http::{HeaderMap, StatusCode};
use identity_application::error::{
    AppError,
    code::AppErrorCode,
    codes::{authorize::AuthorizeErrorCode, common::CommonErrorCode},
    kind::ErrorKind,
};
use identity_domain::openid_connect::{OAuthErrorCode, OAuthErrorResponse};
use identity_infrastructure::{AppState, i18n::resolve_locale_from_headers};

use crate::controllers::response::error_message;

pub(super) fn authorize_error_status(kind: ErrorKind) -> StatusCode {
    match kind {
        ErrorKind::Internal => StatusCode::INTERNAL_SERVER_ERROR,
        ErrorKind::Gone => StatusCode::GONE,
        _ => StatusCode::BAD_REQUEST,
    }
}

pub(in crate::controllers::oauth2) fn authorize_oauth_error_code(
    error: &AppError,
) -> OAuthErrorCode {
    if error.kind() == ErrorKind::Internal {
        return OAuthErrorCode::ServerError;
    }

    match error.code() {
        c if c == CommonErrorCode::InvalidTarget.code() => OAuthErrorCode::InvalidTarget,
        code if code == AuthorizeErrorCode::ResponseTypeInvalid.code() => {
            OAuthErrorCode::UnsupportedResponseType
        }
        code if code == CommonErrorCode::InvalidScope.code()
            || code == AuthorizeErrorCode::ScopeInvalid.code()
            || code == AuthorizeErrorCode::OpenidScopeRequired.code()
            || code == AuthorizeErrorCode::ScopeNotAssignedToClient.code() =>
        {
            OAuthErrorCode::InvalidScope
        }
        code if code == AuthorizeErrorCode::RequestUriInvalid.code()
            || (AuthorizeErrorCode::RequestUriNotHttps.code()
                ..=AuthorizeErrorCode::RequestUriReadFailed.code())
                .contains(&code) =>
        {
            OAuthErrorCode::InvalidRequestUri
        }
        code if (AuthorizeErrorCode::RequestObjectHeaderInvalid.code()
            ..=AuthorizeErrorCode::RequestObjectPayloadInvalid.code())
            .contains(&code) =>
        {
            OAuthErrorCode::InvalidRequestObject
        }
        code if code == AuthorizeErrorCode::RequestObjectEncryptionUnsupported.code() => {
            OAuthErrorCode::RequestNotSupported
        }
        code if code == AuthorizeErrorCode::ClientGrantNotAllowed.code() => {
            OAuthErrorCode::UnauthorizedClient
        }
        _ => OAuthErrorCode::InvalidRequest,
    }
}

pub(super) fn localized_authorize_error_response(
    ctx: &AppState,
    headers: &HeaderMap,
    error: &AppError,
) -> OAuthErrorResponse {
    oauth_error_response(ctx, headers, authorize_oauth_error_code(error), Some(error))
}

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
    use http::{HeaderMap, HeaderValue, StatusCode, header};
    use identity_application::error::{
        AppError,
        codes::{authorize::AuthorizeErrorCode, common::CommonErrorCode},
        kind::ErrorKind,
    };
    use identity_domain::openid_connect::OAuthErrorCode;
    use identity_infrastructure::test_app_state_with_mock_settings;

    use super::{authorize_error_status, authorize_oauth_error_code, oauth_error_response};

    #[tokio::test]
    async fn protocol_errors_use_the_same_localized_response_format() {
        let ctx = test_app_state_with_mock_settings().await;
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

    #[test]
    fn authorize_error_status_preserves_http_error_semantics() {
        assert_eq!(
            authorize_error_status(ErrorKind::Validation),
            StatusCode::BAD_REQUEST
        );
        assert_eq!(authorize_error_status(ErrorKind::Gone), StatusCode::GONE);
        assert_eq!(
            authorize_error_status(ErrorKind::Internal),
            StatusCode::INTERNAL_SERVER_ERROR
        );
    }

    #[test]
    fn authorize_oauth_error_code_maps_protocol_errors() {
        assert_eq!(
            authorize_oauth_error_code(&AppError::from_code(
                AuthorizeErrorCode::ResponseTypeInvalid
            )),
            OAuthErrorCode::UnsupportedResponseType
        );
        assert_eq!(
            authorize_oauth_error_code(&AppError::from_code(AuthorizeErrorCode::ScopeInvalid)),
            OAuthErrorCode::InvalidScope
        );
        assert_eq!(
            authorize_oauth_error_code(&AppError::from_code(
                AuthorizeErrorCode::ClientGrantNotAllowed
            )),
            OAuthErrorCode::UnauthorizedClient
        );
        assert_eq!(
            authorize_oauth_error_code(&AppError::from_code(CommonErrorCode::InternalError)),
            OAuthErrorCode::ServerError
        );
    }
}
