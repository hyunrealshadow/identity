use http::{HeaderValue, StatusCode, header};
use salvo::{Depot, Request, Response, handler};
use serde::Deserialize;

use crate::web::controllers::response::{AppResponse, app_state, json_response, parse_form};
use crate::{
    application::error::{AppError, kind::ErrorKind},
    boot::AppState,
};

#[derive(Debug, Deserialize)]
pub(crate) struct UserInfoForm {
    access_token: Option<String>,
}

#[handler]
pub async fn userinfo(depot: &mut Depot, req: &mut Request) -> Result<AppResponse, AppError> {
    let ctx = app_state(depot)?;
    let headers = req.headers().clone();
    let auth_header = headers.get("Authorization").and_then(|v| v.to_str().ok());

    let bearer_token = match auth_header {
        Some(header) if header.starts_with("Bearer ") => &header[7..],
        Some(_) => {
            return Ok(build_error_response(
                StatusCode::UNAUTHORIZED,
                "invalid_request",
                "Authorization header must use Bearer scheme",
            )
            .into());
        }
        None => {
            return Ok(build_error_response(
                StatusCode::UNAUTHORIZED,
                "invalid_request",
                "Authorization header is required",
            )
            .into());
        }
    };

    Ok(handle_userinfo_request(ctx, bearer_token).await.into())
}

#[handler]
pub async fn userinfo_post(depot: &mut Depot, req: &mut Request) -> Result<AppResponse, AppError> {
    let ctx = app_state(depot)?;
    let headers = req.headers().clone();
    let form: UserInfoForm = parse_form(req).await?;
    // Token may come from Authorization header or POST body
    let auth_header = headers.get("Authorization").and_then(|v| v.to_str().ok());

    let bearer_token: String = if let Some(header) = auth_header {
        if let Some(token) = header.strip_prefix("Bearer ") {
            token.to_string()
        } else {
            return Ok(build_error_response(
                StatusCode::UNAUTHORIZED,
                "invalid_request",
                "Authorization header must use Bearer scheme",
            )
            .into());
        }
    } else if let Some(token) = form.access_token {
        token
    } else {
        return Ok(build_error_response(
            StatusCode::UNAUTHORIZED,
            "invalid_request",
            "Bearer token required in Authorization header or access_token parameter",
        )
        .into());
    };

    Ok(handle_userinfo_request(ctx, &bearer_token).await.into())
}

async fn handle_userinfo_request(ctx: AppState, token: &str) -> Response {
    let service = ctx.services().user_info();

    let token_claims = match service.validate_access_token(token).await {
        Ok(claims) => claims,
        Err(error) => return build_error_from_app_error(error),
    };

    let user_claims = match service
        .get_user_info(
            token_claims.user_oid,
            token_claims.client_oid,
            &token_claims.scope,
            token_claims.claims.as_ref(),
        )
        .await
    {
        Ok(claims) => claims,
        Err(error) => return build_error_from_app_error(error),
    };

    build_success_response(user_claims)
}

fn build_success_response(
    claims: crate::application::openid_connect::dto::UserInfoClaims,
) -> Response {
    let mut response = json_response(StatusCode::OK, claims);
    response.headers_mut().insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("no-store, no-cache, must-revalidate"),
    );
    response
        .headers_mut()
        .insert(header::PRAGMA, HeaderValue::from_static("no-cache"));
    response
}

fn build_error_response(status: StatusCode, error_code: &str, error_description: &str) -> Response {
    let error_body = serde_json::json!({
        "error": error_code,
        "error_description": error_description
    });

    let mut response = json_response(status, error_body);
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    if let Ok(value) = HeaderValue::from_str(&format!("Bearer error=\"{}\"", error_code)) {
        response
            .headers_mut()
            .insert(header::WWW_AUTHENTICATE, value);
    }
    response
}

fn build_error_from_app_error(error: AppError) -> Response {
    match error.kind() {
        ErrorKind::Unauthorized => build_error_response(
            StatusCode::UNAUTHORIZED,
            "invalid_token",
            "The access token is invalid",
        ),
        ErrorKind::Forbidden => build_error_response(
            StatusCode::FORBIDDEN,
            "insufficient_scope",
            "The access token does not have the required scope",
        ),
        ErrorKind::NotFound => {
            build_error_response(StatusCode::NOT_FOUND, "invalid_request", "User not found")
        }
        _ => build_error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "server_error",
            "Internal server error",
        ),
    }
}
