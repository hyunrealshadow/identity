use http::{HeaderMap, HeaderValue, StatusCode, header};
use salvo::{Depot, Request, Response, Writer, async_trait, handler};
use serde::{Deserialize, Serialize};

use identity_application::{
    error::{AppError, code::AppErrorCode, codes::token::TokenErrorCode, kind::ErrorKind},
    openid_connect::token::TokenIntrospectionParams,
};
use identity_domain::openid_connect::ClientAssertionType;

use super::token_endpoint::parse_basic_client_auth;
use crate::controllers::response::{
    AppResponse, app_state, error_message, insert_no_store_headers, json_response, parse_form,
};
use crate::infrastructure::i18n::{error_i18n, resolve_locale_from_headers};

#[derive(Debug, Deserialize)]
struct IntrospectionForm {
    token: String,
    /// RFC 7009 hints are optional and may be ignored; both supported token
    /// formats are checked so a wrong hint never prevents introspection.
    #[serde(rename = "token_type_hint")]
    _token_type_hint: Option<String>,
    client_id: Option<String>,
    client_secret: Option<String>,
    client_assertion_type: Option<String>,
    client_assertion: Option<String>,
}

#[derive(Serialize)]
struct IntrospectionErrorBody {
    error: &'static str,
    error_description: String,
}

pub struct IntrospectionWebError(AppError);

impl From<AppError> for IntrospectionWebError {
    fn from(error: AppError) -> Self {
        Self(error)
    }
}

fn error_code(error: &AppError) -> &'static str {
    let code = error.code();
    if [
        TokenErrorCode::ClientNotFound,
        TokenErrorCode::ClientIdInvalid,
        TokenErrorCode::ClientCredentialsInvalid,
        TokenErrorCode::ClientAuthRequired,
        TokenErrorCode::AssertionIssMissing,
        TokenErrorCode::AssertionSubMissing,
        TokenErrorCode::AssertionVerifyFailed,
        TokenErrorCode::AssertionExpired,
        TokenErrorCode::AssertionNotYetValid,
        TokenErrorCode::AssertionHeaderInvalid,
        TokenErrorCode::AssertionAlgUnsupported,
        TokenErrorCode::AssertionKeyInvalid,
        TokenErrorCode::AssertionAudMismatch,
        TokenErrorCode::AssertionIssSubMismatch,
    ]
    .iter()
    .any(|candidate| code == candidate.code())
    {
        "invalid_client"
    } else if error.kind() == ErrorKind::Internal {
        "server_error"
    } else {
        "invalid_request"
    }
}

#[async_trait]
impl Writer for IntrospectionWebError {
    async fn write(self, req: &mut Request, _depot: &mut Depot, res: &mut Response) {
        let code = error_code(&self.0);
        let status = match code {
            "invalid_client" => StatusCode::UNAUTHORIZED,
            "server_error" => StatusCode::INTERNAL_SERVER_ERROR,
            _ => StatusCode::BAD_REQUEST,
        };
        let description = error_i18n()
            .map(|i18n| error_message(i18n, &resolve_locale_from_headers(req.headers()), &self.0))
            .unwrap_or_else(|| self.0.code().to_string());
        *res = json_response(
            status,
            IntrospectionErrorBody {
                error: code,
                error_description: description,
            },
        );
        insert_no_store_headers(res);
        if status == StatusCode::UNAUTHORIZED && req.headers().get(header::AUTHORIZATION).is_some()
        {
            res.headers_mut().insert(
                header::WWW_AUTHENTICATE,
                HeaderValue::from_static("Basic realm=\"oauth2/introspect\""),
            );
        }
    }
}

#[handler]
pub async fn introspect(
    depot: &mut Depot,
    req: &mut Request,
) -> Result<AppResponse, IntrospectionWebError> {
    let state = app_state(depot)?;
    let headers: HeaderMap = req.headers().clone();
    let form: IntrospectionForm = parse_form(req).await?;
    if form.token.is_empty() {
        return Err(IntrospectionWebError(AppError::from_code(
            TokenErrorCode::RefreshTokenInvalid,
        )));
    }
    let basic = parse_basic_client_auth(&headers);
    if headers.get(header::AUTHORIZATION).is_some() && basic.is_none() {
        return Err(IntrospectionWebError(AppError::from_code(
            TokenErrorCode::ClientCredentialsInvalid,
        )));
    }
    if basic.is_some()
        && (form.client_secret.is_some()
            || form.client_assertion.is_some()
            || form
                .client_id
                .as_ref()
                .is_some_and(|id| Some(id.as_str()) != basic.as_ref().map(|(id, _)| id.as_str())))
    {
        return Err(IntrospectionWebError(AppError::from_code(
            TokenErrorCode::RefreshTokenInvalid,
        )));
    }
    let client_assertion_type = form
        .client_assertion_type
        .as_deref()
        .map(str::parse::<ClientAssertionType>)
        .transpose()
        .map_err(|_| {
            IntrospectionWebError(AppError::from_code(TokenErrorCode::AssertionVerifyFailed))
        })?;
    let client_id = basic.as_ref().map(|(id, _)| id.clone()).or(form.client_id);
    let client_secret = basic
        .as_ref()
        .map(|(_, secret)| secret.clone())
        .or(form.client_secret);
    let result = state
        .services()
        .oidc_token()
        .introspect_token(TokenIntrospectionParams {
            token: form.token,
            client_id,
            client_secret,
            client_secret_basic: basic.is_some(),
            client_assertion_type,
            client_assertion: form.client_assertion,
        })
        .await?;

    let mut response = json_response(StatusCode::OK, result);
    insert_no_store_headers(&mut response);
    Ok(AppResponse(response))
}
#[cfg(test)]
mod tests {
    use http::{StatusCode, header};
    use salvo::{
        Service,
        test::{ResponseExt, TestClient},
    };
    #[tokio::test]
    async fn introspection_route_requires_authentication_and_token() {
        let state = identity_infrastructure::test_app_state_with_cors_origin(None).await;
        let service = Service::new(
            crate::controllers::oauth2::routes().hoop(salvo::affix_state::inject(state)),
        );
        let mut response = TestClient::post("http://127.0.0.1:5800/oauth2/introspect")
            .add_header(
                header::CONTENT_TYPE,
                "application/x-www-form-urlencoded",
                true,
            )
            .body("token=unknown&token_type_hint=unrecognized")
            .send(&service)
            .await;
        assert_eq!(response.status_code, Some(StatusCode::UNAUTHORIZED));
        assert_eq!(
            response.headers().get(header::CACHE_CONTROL).unwrap(),
            "no-store"
        );
        let json: serde_json::Value =
            serde_json::from_str(&response.take_string().await.unwrap()).unwrap();
        assert_eq!(json["error"], "invalid_client");
        let response = TestClient::post("http://127.0.0.1:5800/oauth2/introspect")
            .add_header(
                header::CONTENT_TYPE,
                "application/x-www-form-urlencoded",
                true,
            )
            .body("client_id=unknown")
            .send(&service)
            .await;
        assert_eq!(response.status_code, Some(StatusCode::BAD_REQUEST));
    }
}
