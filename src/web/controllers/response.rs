use std::error::Error as StdError;

use http::{HeaderName, HeaderValue, StatusCode, header};
use salvo::{Depot, Request, Response, Writer, async_trait, prelude::Json, writing::Text};
use serde::{Serialize, de::DeserializeOwned};
use unic_langid::LanguageIdentifier;

use crate::{
    application::error::{AppError, codes::common::CommonErrorCode},
    boot::AppState,
    infrastructure::i18n::{I18n, error_i18n, resolve_locale_from_headers},
    web::views::auth::BusinessErrorResponse,
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

#[async_trait]
impl Writer for AppResponse {
    async fn write(self, _req: &mut Request, _depot: &mut Depot, res: &mut Response) {
        *res = self.0;
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

pub fn render_app_error(res: &mut Response, error: AppError) {
    if let Some(i18n) = error_i18n() {
        let locale = i18n.fallback_locale().clone();
        write_error_response(res, i18n, &locale, error);
    } else {
        let status = error.kind().http_status();
        let body = BusinessErrorResponse::new(error.code(), error.code().to_string());
        render_json(res, status, body);
    }
}

#[async_trait]
impl Writer for AppError {
    async fn write(self, req: &mut Request, _depot: &mut Depot, res: &mut Response) {
        if let Some(i18n) = error_i18n() {
            let locale = resolve_locale_from_headers(req.headers());
            write_error_response(res, i18n, &locale, self);
        } else {
            render_app_error(res, self);
        }
    }
}
