use crate::error::error_message;
use http::{HeaderMap, StatusCode};
use identity_application::error::{
    AppError, ErrorCode,
    codes::{authorize::AuthorizeErrorCode, common::CommonErrorCode},
    kind::ErrorKind,
};
use identity_domain::openid_connect::{OAuthErrorCode, OAuthErrorResponse};
use identity_infrastructure::{AppState, i18n::resolve_locale_from_headers};

pub(super) fn authorize_error_status(kind: ErrorKind) -> StatusCode {
    match kind {
        ErrorKind::Internal => StatusCode::INTERNAL_SERVER_ERROR,
        ErrorKind::Gone => StatusCode::GONE,
        _ => StatusCode::BAD_REQUEST,
    }
}

fn authorize_code_to_oauth(code: AuthorizeErrorCode) -> OAuthErrorCode {
    match code {
        AuthorizeErrorCode::ResponseTypeInvalid => OAuthErrorCode::UnsupportedResponseType,
        AuthorizeErrorCode::ScopeInvalid
        | AuthorizeErrorCode::OpenidScopeRequired
        | AuthorizeErrorCode::ScopeNotAssignedToClient => OAuthErrorCode::InvalidScope,
        AuthorizeErrorCode::RequestUriInvalid
        | AuthorizeErrorCode::RequestUriNotHttps
        | AuthorizeErrorCode::RequestUriHasFragment
        | AuthorizeErrorCode::RequestUriUnsafeHost
        | AuthorizeErrorCode::RequestUriNotRegistered
        | AuthorizeErrorCode::RequestUriFetchFailed
        | AuthorizeErrorCode::RequestUriNot200
        | AuthorizeErrorCode::RequestUriTooLarge
        | AuthorizeErrorCode::RequestUriReadFailed => OAuthErrorCode::InvalidRequestUri,
        AuthorizeErrorCode::RequestObjectHeaderInvalid
        | AuthorizeErrorCode::RequestObjectDecodeFailed
        | AuthorizeErrorCode::RequestObjectAlgUnsupported
        | AuthorizeErrorCode::RequestObjectKeyInvalid
        | AuthorizeErrorCode::RequestObjectVerifyFailed
        | AuthorizeErrorCode::RequestObjectIssMismatch
        | AuthorizeErrorCode::RequestObjectAudMismatch
        | AuthorizeErrorCode::RequestObjectExpired
        | AuthorizeErrorCode::RequestObjectNotYetValid
        | AuthorizeErrorCode::RequestObjectIatFuture
        | AuthorizeErrorCode::RequestObjectFieldMismatch
        | AuthorizeErrorCode::RequestObjectJsonInvalid
        | AuthorizeErrorCode::ClaimsParamInvalid
        | AuthorizeErrorCode::ClaimsNotObject
        | AuthorizeErrorCode::ClaimsFieldNotObject
        | AuthorizeErrorCode::RequestObjectEncodingInvalid
        | AuthorizeErrorCode::RequestObjectBase64Invalid
        | AuthorizeErrorCode::RequestObjectPayloadInvalid => OAuthErrorCode::InvalidRequestObject,
        AuthorizeErrorCode::RequestObjectEncryptionUnsupported => {
            OAuthErrorCode::RequestNotSupported
        }
        AuthorizeErrorCode::ClientGrantNotAllowed => OAuthErrorCode::UnauthorizedClient,
        AuthorizeErrorCode::ClientLookupFailed
        | AuthorizeErrorCode::CredentialLookupFailed
        | AuthorizeErrorCode::SerializeRequestFailed
        | AuthorizeErrorCode::StoreRequestFailed
        | AuthorizeErrorCode::StoreLoginFailed
        | AuthorizeErrorCode::LoadRequestFailed
        | AuthorizeErrorCode::DeserializeRequestFailed
        | AuthorizeErrorCode::StoredClientIdInvalid
        | AuthorizeErrorCode::LoadLoginFailed
        | AuthorizeErrorCode::StoredRedirectUriInvalid
        | AuthorizeErrorCode::SerializeCodeFailed
        | AuthorizeErrorCode::StoreCodeFailed
        | AuthorizeErrorCode::StoredSessionIdInvalid
        | AuthorizeErrorCode::EncryptionKeyNotFound
        | AuthorizeErrorCode::EncryptionFailed => OAuthErrorCode::ServerError,
        AuthorizeErrorCode::ClientIdInvalid
        | AuthorizeErrorCode::ClientNotFound
        | AuthorizeErrorCode::ResponseModeInvalid
        | AuthorizeErrorCode::RedirectUriInvalid
        | AuthorizeErrorCode::DisplayValueInvalid
        | AuthorizeErrorCode::PromptValueInvalid
        | AuthorizeErrorCode::PromptNoneCombined
        | AuthorizeErrorCode::MaxAgeInvalid
        | AuthorizeErrorCode::CodeChallengeMethodInvalid
        | AuthorizeErrorCode::RequestAndUriConflict
        | AuthorizeErrorCode::RequiredParamMissing
        | AuthorizeErrorCode::RedirectUriNotRegistered
        | AuthorizeErrorCode::AuthzRequestNotFound
        | AuthorizeErrorCode::AuthzRequestTypeMismatch
        | AuthorizeErrorCode::LoginNotFound
        | AuthorizeErrorCode::LoginIdInvalid
        | AuthorizeErrorCode::ImplicitNonceRequired
        | AuthorizeErrorCode::ImplicitUserNotFound
        | AuthorizeErrorCode::IdTokenHintIssuerInvalid
        | AuthorizeErrorCode::AuthzInteractionConflict
        | AuthorizeErrorCode::InitiateLoginUriNotRegistered => OAuthErrorCode::InvalidRequest,
    }
}

pub(in crate::controllers::oauth2) fn authorize_oauth_error_code(
    error: &AppError,
) -> OAuthErrorCode {
    if error.kind() == ErrorKind::Internal {
        return OAuthErrorCode::ServerError;
    }

    match error.error_code() {
        ErrorCode::Common(CommonErrorCode::InvalidTarget) => OAuthErrorCode::InvalidTarget,
        ErrorCode::Common(CommonErrorCode::InvalidScope) => OAuthErrorCode::InvalidScope,
        ErrorCode::Authorize(code) => authorize_code_to_oauth(code),
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
        codes::{authorize, common},
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
            authorize_oauth_error_code(
                &authorize::error::ResponseTypeInvalid::new("unknown").into()
            ),
            OAuthErrorCode::UnsupportedResponseType
        );
        assert_eq!(
            authorize_oauth_error_code(&authorize::error::ScopeInvalid.into()),
            OAuthErrorCode::InvalidScope
        );
        assert_eq!(
            authorize_oauth_error_code(&authorize::error::ClientGrantNotAllowed.into()),
            OAuthErrorCode::UnauthorizedClient
        );
        assert_eq!(
            authorize_oauth_error_code(&common::error::InternalError.into()),
            OAuthErrorCode::ServerError
        );
    }
}
