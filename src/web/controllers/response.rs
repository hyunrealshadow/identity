use std::{error::Error as StdError, mem};

use http::{HeaderMap, HeaderName, HeaderValue, StatusCode, header};
use identity_application::error::ErrorDiagnostics;
use salvo::{Depot, Request, Response, Writer, async_trait, handler, prelude::Json, writing::Text};
use serde::{Serialize, de::DeserializeOwned};
use tracing::{Level, error, event};
use unic_langid::LanguageIdentifier;

use crate::{
    application::error::{
        AppError, codes::common::CommonErrorCode, kind::ErrorKind, params::ErrorParams,
    },
    boot::AppState,
    infrastructure::{
        i18n::{I18n, error_i18n, resolve_locale_from_headers},
        web,
    },
    web::views::{
        auth::{BusinessErrorResponse, FieldErrorDetail},
        oauth2::ErrorPageData,
    },
};

pub fn error_http_status(kind: ErrorKind) -> StatusCode {
    match kind {
        ErrorKind::NotFound => StatusCode::NOT_FOUND,
        ErrorKind::Unauthorized => StatusCode::UNAUTHORIZED,
        ErrorKind::Forbidden => StatusCode::FORBIDDEN,
        ErrorKind::Conflict => StatusCode::CONFLICT,
        ErrorKind::Validation => StatusCode::UNPROCESSABLE_ENTITY,
        ErrorKind::RateLimit => StatusCode::TOO_MANY_REQUESTS,
        ErrorKind::Gone => StatusCode::GONE,
        ErrorKind::Internal => StatusCode::INTERNAL_SERVER_ERROR,
    }
}

pub fn error_message(i18n: &I18n, locale: &LanguageIdentifier, error: &AppError) -> String {
    localized_error_message(i18n, locale, error.code(), error.params())
}

pub fn app_error_log_level(error: &AppError) -> Level {
    match error.kind() {
        ErrorKind::Internal => Level::ERROR,
        ErrorKind::Unauthorized | ErrorKind::Forbidden | ErrorKind::RateLimit => Level::WARN,
        ErrorKind::NotFound | ErrorKind::Conflict | ErrorKind::Validation | ErrorKind::Gone => {
            Level::DEBUG
        }
    }
}

pub fn log_app_error(error: &AppError, message: &'static str) {
    let diagnostics = ErrorDiagnostics::from_error(error);
    macro_rules! log {
        ($level:expr) => {
            event!(
                $level,
                error_code = error.code(),
                error_kind = ?error.kind(),
                error = %error,
                has_source = error.source().is_some(),
                error_cause = %diagnostics.cause,
                error_operation = diagnostics.operation,
                stacktrace = diagnostics.backtrace.map(ToString::to_string),
                "{message}"
            )
        };
    }
    match app_error_log_level(error) {
        Level::ERROR => log!(Level::ERROR),
        Level::WARN => log!(Level::WARN),
        _ => log!(Level::DEBUG),
    }
}

fn localized_error_message(
    i18n: &I18n,
    locale: &LanguageIdentifier,
    code: u32,
    params: &ErrorParams,
) -> String {
    if let Some(message) = params.get("message").filter(|message| !message.is_empty()) {
        return message.to_owned();
    }

    if params.is_empty() {
        i18n.t_code(locale, code)
    } else {
        i18n.t_code_with_params(locale, code, params)
    }
}

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
        .map_err(|_| AppError::from_code(CommonErrorCode::InternalError))
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

/// JSON-only error wrapper for REST endpoints (`/oauth2/token`, `/oauth2/userinfo`,
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
        if accepts_html(req.headers())
            && let Ok(ctx) = app_state(depot)
        {
            render_error_page(res, req.headers(), &ctx, self.0);
            return;
        }

        if let Some(i18n) = error_i18n() {
            let locale = resolve_locale_from_headers(req.headers());
            write_error_response(res, i18n, &locale, self.0);
        } else {
            render_unlocalized_app_error(res, self.0);
        }
    }
}

#[async_trait]
impl Writer for JsonWebError {
    async fn write(self, req: &mut Request, _depot: &mut Depot, res: &mut Response) {
        if let Some(i18n) = error_i18n() {
            let locale = resolve_locale_from_headers(req.headers());
            write_error_response(res, i18n, &locale, self.0);
        } else {
            render_unlocalized_app_error(res, self.0);
        }
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
        .map_err(|_| AppError::from_code(CommonErrorCode::InvalidRequest))
}

pub async fn parse_form<T: DeserializeOwned>(req: &mut Request) -> Result<T, AppError> {
    req.parse_form()
        .await
        .map_err(|_| AppError::from_code(CommonErrorCode::InvalidRequest))
}

pub fn parse_query<T: DeserializeOwned>(req: &mut Request) -> Result<T, AppError> {
    req.parse_queries()
        .map_err(|_| AppError::from_code(CommonErrorCode::InvalidRequest))
}

pub fn parse_param<T: DeserializeOwned>(req: &Request, name: &str) -> Result<T, AppError> {
    req.param(name)
        .ok_or_else(|| AppError::from_code(CommonErrorCode::InvalidRequest))
}

pub fn write_error_response(
    res: &mut Response,
    i18n: &I18n,
    locale: &LanguageIdentifier,
    error: AppError,
) {
    let status = error_http_status(error.kind());

    log_app_error(&error, "application request failed");

    let message = error_message(i18n, locale, &error);
    let fields = error
        .validation()
        .map(|validation| {
            validation
                .fields()
                .iter()
                .map(|field_error| FieldErrorDetail {
                    field: field_error.field().to_owned(),
                    code: field_error.code(),
                    message: localized_error_message(
                        i18n,
                        locale,
                        field_error.code(),
                        field_error.params(),
                    ),
                })
                .collect()
        })
        .unwrap_or_default();
    let body = BusinessErrorResponse::new(error.code(), message).with_fields(fields);
    render_json(res, status, body);
}

pub fn render_app_error(res: &mut Response, headers: &HeaderMap, ctx: &AppState, error: AppError) {
    if accepts_html(headers) {
        render_error_page(res, headers, ctx, error);
        return;
    }

    if let Some(i18n) = error_i18n() {
        let locale = i18n.fallback_locale().clone();
        write_error_response(res, i18n, &locale, error);
    } else {
        render_unlocalized_app_error(res, error);
    }
}

pub fn render_error_page(res: &mut Response, headers: &HeaderMap, ctx: &AppState, error: AppError) {
    let status = error_http_status(error.kind());

    log_app_error(&error, "application request failed (html)");

    let i18n = ctx.resources().i18n();
    let locale = resolve_locale_from_headers(headers);
    let message = error_message(i18n, &locale, &error);

    let data = ErrorPageData {
        status_code: status.as_u16(),
        oauth_error_code: None,
        error_code: Some(error.code()),
        title: i18n.t(&locale, "error-page-title"),
        message,
        details: Vec::new(),
    };

    match web::tera::render_view(ctx, headers, "error.html", data) {
        Ok(body) => render_html(res, status, body),
        Err(e) => {
            error!(error = %e, "render_error_page: template render failed");
            let body = BusinessErrorResponse::new(error.code(), error.to_string());
            render_json(res, StatusCode::INTERNAL_SERVER_ERROR, body);
        }
    }
}

fn render_unlocalized_app_error(res: &mut Response, error: AppError) {
    log_app_error(&error, "application request failed without localization");
    let status = error_http_status(error.kind());
    let message = error
        .params()
        .get("message")
        .filter(|message| !message.is_empty())
        .map(str::to_owned)
        .unwrap_or_else(|| error.code().to_string());
    let fields = error
        .validation()
        .map(|validation| {
            validation
                .fields()
                .iter()
                .map(|field_error| FieldErrorDetail {
                    field: field_error.field().to_owned(),
                    code: field_error.code(),
                    message: field_error
                        .params()
                        .get("message")
                        .filter(|message| !message.is_empty())
                        .map(str::to_owned)
                        .unwrap_or_else(|| field_error.code().to_string()),
                })
                .collect()
        })
        .unwrap_or_default();
    let body = BusinessErrorResponse::new(error.code(), message).with_fields(fields);
    render_json(res, status, body);
}

pub fn render_app_error_json(res: &mut Response, error: AppError) {
    if let Some(i18n) = error_i18n() {
        let locale = i18n.fallback_locale().clone();
        write_error_response(res, i18n, &locale, error);
    } else {
        render_unlocalized_app_error(res, error);
    }
}

#[handler]
pub async fn handle_404(req: &mut Request, depot: &mut Depot, res: &mut Response) {
    let status = StatusCode::NOT_FOUND;

    if accepts_html(req.headers())
        && let Ok(ctx) = app_state(depot)
    {
        let i18n = ctx.resources().i18n();
        let locale = resolve_locale_from_headers(req.headers());
        let message = i18n.t(&locale, "error-404-message");

        let data = ErrorPageData {
            status_code: status.as_u16(),
            oauth_error_code: None,
            error_code: None,
            title: i18n.t(&locale, "error-404-title"),
            message,
            details: Vec::new(),
        };

        match web::tera::render_view(&ctx, req.headers(), "error.html", data) {
            Ok(body) => {
                render_html(res, status, body);
                return;
            }
            Err(e) => error!(error = %e, "handle_404: template render failed"),
        }
    }

    let body = BusinessErrorResponse::new(
        status.as_u16().into(),
        status.canonical_reason().unwrap_or("Not Found"),
    );
    render_json(res, status, body);
}

#[cfg(test)]
mod tests {
    use std::{
        io::{Error, ErrorKind, Result as IoResult, Write},
        sync::{Arc, Mutex},
    };

    use http::StatusCode;
    use identity_application::error::{ErrorContext, ErrorDiagnostics};
    use salvo::{
        Router, Service, handler,
        test::{ResponseExt, TestClient},
    };
    use tracing::{Level, subscriber::with_default};
    use tracing_subscriber::fmt;

    use super::{JsonWebResult, WebResult, log_app_error};
    use crate::{
        application::error::{
            AppError,
            codes::{
                authorize_http::AuthorizeHttpErrorCode, common::CommonErrorCode,
                install::InstallErrorCode,
            },
        },
        infrastructure::{i18n::init_error_i18n, web::tera::build_i18n},
    };

    #[test]
    fn logs_distinguish_internal_failures_rejections_and_validation() {
        #[derive(Clone)]
        struct Capture(Arc<Mutex<Vec<u8>>>);
        impl Write for Capture {
            fn write(&mut self, bytes: &[u8]) -> IoResult<usize> {
                self.0.lock().unwrap().extend_from_slice(bytes);
                Ok(bytes.len())
            }
            fn flush(&mut self) -> IoResult<()> {
                Ok(())
            }
        }
        let bytes = Arc::new(Mutex::new(Vec::new()));
        let writer = Capture(bytes.clone());
        let subscriber = fmt()
            .with_ansi(false)
            .without_time()
            .with_max_level(Level::TRACE)
            .with_writer(move || writer.clone())
            .finish();
        with_default(subscriber, || {
            let error =
                AppError::from_code(CommonErrorCode::InternalError).with_source(ErrorContext::new(
                    "client_authorization.lock_refresh_family",
                    Error::other("database unavailable"),
                ));
            log_app_error(&error, "internal-test");
            log_app_error(
                &AppError::from_code(CommonErrorCode::Unauthorized),
                "rejection-test",
            );
            log_app_error(
                &AppError::from_code(CommonErrorCode::InvalidRequest),
                "validation-test",
            );
        });
        let output = String::from_utf8(bytes.lock().unwrap().clone()).unwrap();
        let internal = output
            .lines()
            .find(|line| line.contains("internal-test"))
            .unwrap();
        assert!(internal.contains("ERROR") && internal.contains("has_source=true"));
        assert!(internal.contains("database unavailable"));
        assert_eq!(internal.matches("database unavailable").count(), 1);
        assert!(internal.contains("error_operation=\"client_authorization.lock_refresh_family\""));
        assert!(internal.contains("stacktrace="));
        assert!(!internal.contains("error_file=") && !internal.contains("app_error_line="));
        assert!(!internal.contains("source_chain") && !internal.contains(" -> "));
        let rejection = output
            .lines()
            .find(|line| line.contains("rejection-test"))
            .unwrap();
        assert!(rejection.contains("WARN") && rejection.contains("has_source=false"));
        let validation = output
            .lines()
            .find(|line| line.contains("validation-test"))
            .unwrap();
        assert!(validation.contains("DEBUG"));
    }

    #[handler]
    async fn direct_app_error() -> WebResult<()> {
        Err(AppError::from_code(AuthorizeHttpErrorCode::ContinueInteractionUnavailable).into())
    }

    #[handler]
    async fn validation_app_error() -> JsonWebResult<()> {
        Err(AppError::from_code(CommonErrorCode::ValidationFailed)
            .with_field_error("email", AppError::from_code(InstallErrorCode::EmailInvalid))
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

    #[test]
    fn diagnostics_preserve_internal_error_details() {
        let error = AppError::from_code(CommonErrorCode::InternalError).with_source(Error::new(
            ErrorKind::ConnectionRefused,
            "database unavailable",
        ));

        assert_eq!(
            ErrorDiagnostics::from_error(&error).cause,
            "database unavailable"
        );
    }
}
