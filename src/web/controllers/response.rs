use std::mem;

use http::{HeaderMap, HeaderName, HeaderValue, StatusCode, header};
use salvo::{
    Depot, FlowCtrl, Request, Response, Writer, async_trait, handler, prelude::Json, writing::Text,
};
use serde::{Serialize, de::DeserializeOwned};
use tracing::error;
use unic_langid::LanguageIdentifier;

use crate::{
    application::error::{AppError, codes::common},
    infrastructure::AppState,
    infrastructure::i18n::{I18n, resolve_locale_from_headers},
    web::{
        error::{
            challenge, error_http_status, error_message, field_errors, log_app_error,
            step_up_www_authenticate, with_request_catalog,
        },
        views::{
            auth::{BusinessErrorResponse, FieldErrorDetail},
            oauth2::ErrorPageData,
        },
    },
};

pub fn accepts_html(headers: &HeaderMap) -> bool {
    headers
        .get_all(header::ACCEPT)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .any(|v| v.contains("text/html"))
}

pub fn app_state(depot: &Depot) -> Result<AppState, AppError> {
    depot
        .get_typed::<AppState>()
        .cloned()
        .map_err(|_| common::error::InternalError.into_error())
}

pub fn render_json<T: Serialize + Send>(res: &mut Response, status: StatusCode, body: T) {
    res.status_code(status);
    res.render(Json(body));
}

pub fn render_html(res: &mut Response, status: StatusCode, body: String) {
    res.status_code(status);
    res.render(Text::Html(body));
}

pub fn render_status(res: &mut Response, status: StatusCode) {
    res.status_code(status);
}

pub fn redirect_to(res: &mut Response, location: &str) {
    redirect(res, StatusCode::SEE_OTHER, location);
}

pub fn redirect_temporary(res: &mut Response, location: &str) {
    redirect(res, StatusCode::TEMPORARY_REDIRECT, location);
}

pub fn redirect_to_response(location: &str) -> Response {
    let mut response = Response::new();
    redirect_to(&mut response, location);
    response
}

pub fn html_response(status: StatusCode, body: String) -> Response {
    let mut response = Response::new();
    render_html(&mut response, status, body);
    response
}

pub fn json_response<T: Serialize + Send>(status: StatusCode, body: T) -> Response {
    let mut response = Response::new();
    render_json(&mut response, status, body);
    response
}

pub struct AppResponse(pub Response);

impl From<Response> for AppResponse {
    fn from(response: Response) -> Self {
        Self(response)
    }
}

pub struct WebError(pub AppError);

pub type WebResult<T = AppResponse> = Result<T, WebError>;

impl From<AppError> for WebError {
    fn from(error: AppError) -> Self {
        Self(error)
    }
}

/// JSON-only error wrapper for REST endpoints (`/oauth2/token`, `/openid/userinfo`,
/// `/oauth2/register`, `/api/*`, ...).
///
/// Unlike `WebError` this **always** renders a JSON body regardless of the
/// `Accept` header: the endpoint, not the client, decides the response format.
/// The human-readable message is resolved through the Fluent i18n system using
/// the request's `Accept-Language`.
pub struct JsonWebError(pub AppError);

pub type JsonWebResult<T> = Result<T, JsonWebError>;

impl From<AppError> for JsonWebError {
    fn from(error: AppError) -> Self {
        Self(error)
    }
}

impl From<WebError> for JsonWebError {
    fn from(error: WebError) -> Self {
        Self(error.0)
    }
}

#[async_trait]
impl Writer for AppResponse {
    async fn write(self, _req: &mut Request, _depot: &mut Depot, res: &mut Response) {
        let AppResponse(mut response) = self;

        if let Some(status) = response.status_code {
            res.status_code(status);
        }
        for (name, value) in response.headers_mut().drain() {
            if let Some(name) = name {
                res.headers_mut().append(name, value);
            }
        }
        *res.body_mut() = mem::take(response.body_mut());
    }
}

#[async_trait]
impl Writer for WebError {
    async fn write(self, req: &mut Request, depot: &mut Depot, res: &mut Response) {
        match app_state(depot) {
            Ok(ctx) => render_app_error(res, req.headers(), &ctx, self.0),
            Err(_) => write_error_response(res, req.headers(), self.0),
        }
    }
}

#[async_trait]
impl Writer for JsonWebError {
    async fn write(self, req: &mut Request, _depot: &mut Depot, res: &mut Response) {
        write_error_response(res, req.headers(), self.0);
    }
}

fn redirect(res: &mut Response, status: StatusCode, location: &str) {
    res.status_code(status);
    if let Ok(value) = HeaderValue::from_str(location) {
        res.headers_mut().insert(header::LOCATION, value);
    }
}

pub fn append_header(res: &mut Response, name: HeaderName, value: HeaderValue) {
    res.headers_mut().append(name, value);
}

pub fn append_set_cookie(res: &mut Response, cookie: &str) {
    if let Ok(value) = HeaderValue::from_str(cookie) {
        append_header(res, header::SET_COOKIE, value);
    }
}

pub fn insert_no_store_headers(res: &mut Response) {
    res.headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    res.headers_mut()
        .insert(header::PRAGMA, HeaderValue::from_static("no-cache"));
}

pub async fn parse_json<T: DeserializeOwned>(req: &mut Request) -> Result<T, AppError> {
    req.parse_json()
        .await
        .map_err(|_| common::error::InvalidRequest.into_error())
}

pub async fn parse_form<T: DeserializeOwned>(req: &mut Request) -> Result<T, AppError> {
    req.parse_form()
        .await
        .map_err(|_| common::error::InvalidRequest.into_error())
}

pub fn parse_query<T: DeserializeOwned>(req: &mut Request) -> Result<T, AppError> {
    req.parse_queries()
        .map_err(|_| common::error::InvalidRequest.into_error())
}

pub fn parse_param<T: DeserializeOwned>(req: &Request, name: &str) -> Result<T, AppError> {
    req.param(name)
        .ok_or_else(|| common::error::InvalidRequest.into_error())
}

/// Write the standard JSON error body in the request's language.
pub fn write_error_response(res: &mut Response, headers: &HeaderMap, error: AppError) {
    log_app_error(&error, "application request failed");
    with_request_catalog(headers, |i18n, locale| {
        write_localized_error(res, i18n, locale, &error);
    });
}

fn write_localized_error(
    res: &mut Response,
    i18n: &I18n,
    locale: &LanguageIdentifier,
    error: &AppError,
) {
    let status = error_http_status(error.kind());
    if status == StatusCode::UNAUTHORIZED
        && let Some(step_up) = error.step_up()
        && let Ok(value) = HeaderValue::from_str(&step_up_www_authenticate("identity", &step_up))
    {
        res.headers_mut().insert(header::WWW_AUTHENTICATE, value);
    }
    let fields = field_errors(i18n, locale, error)
        .into_iter()
        .map(|field| FieldErrorDetail {
            field: field.field,
            code: field.code,
            message: field.message,
        })
        .collect();
    let body = BusinessErrorResponse::new(error.code(), error_message(i18n, locale, error))
        .with_fields(fields)
        .with_challenge(challenge(error));
    render_json(res, status, body);
}

/// Render an error as an HTML page for browsers that accept one, otherwise
/// as the standard JSON error body.
pub fn render_app_error(res: &mut Response, headers: &HeaderMap, ctx: &AppState, error: AppError) {
    if accepts_html(headers) {
        render_error_page(res, headers, ctx, error);
    } else {
        write_error_response(res, headers, error);
    }
}

pub fn render_error_page(res: &mut Response, headers: &HeaderMap, ctx: &AppState, error: AppError) {
    let status = error_http_status(error.kind());

    log_app_error(&error, "application request failed (html)");

    let i18n = ctx.resources().i18n();
    let locale = resolve_locale_from_headers(headers);
    let message = error_message(i18n, &locale, &error);

    let data = ErrorPageData::new(
        status.as_u16(),
        None,
        Some(error.code()),
        i18n.t(&locale, "error-page-title"),
        message.clone(),
    );

    match crate::views::render::render_view(ctx, headers, "error.html", data) {
        Ok(body) => render_html(res, status, body),
        Err(e) => {
            error!(error = %e, "render_error_page: template render failed");
            render_json(
                res,
                status,
                BusinessErrorResponse::new(error.code(), message),
            );
        }
    }
}

/// Answer a request nothing served: an HTML page when the client accepts
/// HTML, otherwise the standard JSON error body. Both carry the not-found
/// error code; the page also shows the request's correlation IDs.
pub fn render_not_found(req: &Request, depot: &Depot, res: &mut Response) {
    let status = StatusCode::NOT_FOUND;
    let error = common::error::NotFound.into_error();
    let Ok(ctx) = app_state(depot) else {
        write_error_response(res, req.headers(), error);
        return;
    };
    let i18n = ctx.resources().i18n();
    let locale = resolve_locale_from_headers(req.headers());

    if accepts_html(req.headers()) {
        let data = ErrorPageData::new(
            status.as_u16(),
            None,
            Some(error.code()),
            i18n.t(&locale, "error-404-title"),
            i18n.t(&locale, "error-404-message"),
        );
        match crate::views::render::render_view(&ctx, req.headers(), "error.html", data) {
            Ok(body) => {
                render_html(res, status, body);
                return;
            }
            Err(e) => error!(error = %e, "not found page: template render failed"),
        }
    }

    let message = error_message(i18n, &locale, &error);
    render_json(
        res,
        status,
        BusinessErrorResponse::new(error.code(), message),
    );
}

/// Route goal for paths that exist only as a prefix, such as `/`: they are
/// not found for every method rather than method-not-allowed.
#[handler]
pub async fn not_found(res: &mut Response) {
    res.status_code(StatusCode::NOT_FOUND);
}

/// Innermost service hoop: a 404 left without a body (no matching route, or
/// a static file that does not exist) gets the not-found answer. Responses a
/// handler already wrote, and every other status such as 405, are untouched.
#[handler]
pub async fn not_found_fallback(
    req: &mut Request,
    depot: &mut Depot,
    res: &mut Response,
    ctrl: &mut FlowCtrl,
) {
    ctrl.call_next(req, depot, res).await;
    if res.status_code == Some(StatusCode::NOT_FOUND) && (res.body.is_none() || res.body.is_error())
    {
        res.take_body();
        render_not_found(req, depot, res);
    }
}

#[cfg(test)]
mod tests {
    use std::io::{Error, ErrorKind};

    use http::StatusCode;
    use identity_application::error::{ErrorDiagnostics, StepUpChallenge};
    use identity_domain::auth::AuthenticationContextClass;
    use salvo::{
        Router, Service, handler,
        test::{ResponseExt, TestClient},
    };

    use super::{JsonWebResult, WebResult, render_app_error, write_error_response};
    use crate::{
        application::error::codes::{authorize, common, install},
        infrastructure::{
            i18n::build_i18n, i18n::init_error_i18n, test_app_state_with_mock_settings,
        },
    };

    #[handler]
    async fn direct_app_error() -> WebResult<()> {
        Err(authorize::error::InteractionUnavailable.into_error().into())
    }

    #[handler]
    async fn validation_app_error() -> JsonWebResult<()> {
        Err(common::error::ValidationFailed::new()
            .with_field_error("email", install::error::EmailInvalid)
            .into())
    }

    #[tokio::test]
    async fn direct_app_error_writer_uses_localized_message() {
        init_error_i18n(build_i18n().expect("i18n should load from assets/i18n"));
        let service = Service::new(Router::with_path("error").get(direct_app_error));

        let mut response = TestClient::get("http://127.0.0.1:5800/error")
            .send(&service)
            .await;

        assert_eq!(response.status_code, Some(StatusCode::GONE));
        let body = response.take_string().await.unwrap();
        assert!(
            body.contains("\"message\":\"This authorization interaction is no longer available.\""),
            "{body}"
        );
    }

    #[tokio::test]
    async fn validation_error_writer_includes_localized_field_errors() {
        init_error_i18n(build_i18n().expect("i18n should load from assets/i18n"));
        let service = Service::new(Router::with_path("validation").post(validation_app_error));

        let mut response = TestClient::post("http://127.0.0.1:5800/validation")
            .send(&service)
            .await;

        assert_eq!(response.status_code, Some(StatusCode::UNPROCESSABLE_ENTITY));
        let body = response.take_string().await.unwrap();
        assert!(body.contains("\"code\":10002"), "{body}");
        assert!(body.contains("\"field\":\"email\""), "{body}");
        assert!(body.contains("\"code\":13006"), "{body}");
        assert!(
            body.contains("\"message\":\"The email address is invalid.\""),
            "{body}"
        );
    }

    #[tokio::test]
    async fn json_errors_follow_the_request_language() {
        init_error_i18n(build_i18n().expect("i18n should load from assets/i18n"));
        let ctx = test_app_state_with_mock_settings().await;
        let mut headers = http::HeaderMap::new();
        headers.insert(
            http::header::ACCEPT,
            http::HeaderValue::from_static("application/json"),
        );
        headers.insert(
            http::header::ACCEPT_LANGUAGE,
            http::HeaderValue::from_static("zh-CN"),
        );
        let mut response = salvo::Response::new();
        render_app_error(
            &mut response,
            &headers,
            &ctx,
            install::error::EmailInvalid.into(),
        );

        assert_eq!(response.status_code, Some(StatusCode::UNPROCESSABLE_ENTITY));
        let body = response.take_string().await.unwrap();
        assert!(body.contains("\"message\":\"邮箱地址格式无效\""), "{body}");
    }

    #[tokio::test]
    async fn json_errors_carry_the_step_up_challenge_and_header() {
        init_error_i18n(build_i18n().expect("i18n should load from assets/i18n"));
        let error = common::error::Unauthorized
            .into_error()
            .with_step_up(StepUpChallenge {
                acr: Some(AuthenticationContextClass::MultiFactor),
                max_age_secs: Some(300),
            });
        let mut response = salvo::Response::new();

        write_error_response(&mut response, &http::HeaderMap::new(), error);

        assert_eq!(response.status_code, Some(StatusCode::UNAUTHORIZED));
        let header = response
            .headers()
            .get(http::header::WWW_AUTHENTICATE)
            .unwrap()
            .to_str()
            .unwrap()
            .to_owned();
        assert!(header.contains("error=\"insufficient_user_authentication\""));
        assert!(header.contains("max_age=\"300\""));
        let body: serde_json::Value =
            serde_json::from_str(&response.take_string().await.unwrap()).unwrap();
        assert_eq!(
            body["error"]["challenge"],
            serde_json::json!({
                "error": "insufficient_user_authentication",
                "acrValues": "aal2",
                "maxAge": 300
            })
        );
    }

    #[test]
    fn diagnostics_preserve_internal_error_details() {
        let error = common::error::InternalError.with_source(Error::new(
            ErrorKind::ConnectionRefused,
            "database unavailable",
        ));

        assert_eq!(
            ErrorDiagnostics::from_error(&error).cause,
            "database unavailable"
        );
    }
}
