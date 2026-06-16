use std::error::Error as StdError;

use http::{HeaderMap, HeaderName, HeaderValue, StatusCode, header};
use salvo::{Depot, Request, Response, Writer, async_trait, handler, prelude::Json, writing::Text};
use serde::{Serialize, de::DeserializeOwned};
use unic_langid::LanguageIdentifier;

use crate::{
    application::error::{AppError, codes::common::CommonErrorCode},
    boot::AppState,
    infrastructure::i18n::{I18n, error_i18n, resolve_locale_from_headers},
    infrastructure::web,
    web::views::{auth::BusinessErrorResponse, oauth2::ErrorPageData},
};

pub fn error_message(i18n: &I18n, locale: &LanguageIdentifier, error: &AppError) -> String {
    if let Some(message) = error
        .params()
        .get("message")
        .filter(|message| !message.is_empty())
    {
        return message.to_owned();
    }

    if error.params().is_empty() {
        i18n.t_code(locale, error.code())
    } else {
        i18n.t_code_with_params(locale, error.code(), error.params())
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
        .obtain::<AppState>()
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
        *res.body_mut() = std::mem::take(response.body_mut());
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
    let status = error.kind().http_status();

    if status.is_server_error() {
        tracing::error!(
            error = %error,
            source = ?error.source(),
            code = error.code(),
            "internal error"
        );
    } else {
        tracing::debug!(error = %error, code = error.code(), "business error");
    }

    let message = error_message(i18n, locale, &error);
    let body = BusinessErrorResponse::new(error.code(), message);
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
    let status = error.kind().http_status();

    if status.is_server_error() {
        tracing::error!(
            error = %error,
            source = ?error.source(),
            code = error.code(),
            "internal error rendered as html"
        );
    }

    let i18n = ctx.resources().i18n();
    let locale = resolve_locale_from_headers(headers);
    let message = error_message(i18n, &locale, &error);

    let data = ErrorPageData {
        status_code: status.as_u16(),
        title: status.canonical_reason().unwrap_or("Error").to_owned(),
        message,
        details: Vec::new(),
    };

    match web::tera::render_view(ctx, headers, "error.html", data) {
        Ok(body) => render_html(res, status, body),
        Err(e) => {
            tracing::error!(error = %e, "render_error_page: template render failed");
            let body = BusinessErrorResponse::new(error.code(), error.to_string());
            render_json(res, StatusCode::INTERNAL_SERVER_ERROR, body);
        }
    }
}

fn render_unlocalized_app_error(res: &mut Response, error: AppError) {
    let status = error.kind().http_status();
    let message = error
        .params()
        .get("message")
        .filter(|message| !message.is_empty())
        .map(str::to_owned)
        .unwrap_or_else(|| error.code().to_string());
    let body = BusinessErrorResponse::new(error.code(), message);
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
            title: i18n.t(&locale, "error-404-title"),
            message,
            details: Vec::new(),
        };

        match web::tera::render_view(&ctx, req.headers(), "error.html", data) {
            Ok(body) => {
                render_html(res, status, body);
                return;
            }
            Err(e) => tracing::error!(error = %e, "handle_404: template render failed"),
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
    use http::StatusCode;
    use salvo::{
        Router, Service, handler,
        test::{ResponseExt, TestClient},
    };

    use super::WebResult;

    use crate::{
        application::error::{AppError, codes::authorize_http::AuthorizeHttpErrorCode},
        infrastructure::{i18n::init_error_i18n, web::tera::build_i18n},
    };

    #[handler]
    async fn direct_app_error() -> WebResult<()> {
        Err(AppError::from_code(AuthorizeHttpErrorCode::ContinueInteractionUnavailable).into())
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
}
