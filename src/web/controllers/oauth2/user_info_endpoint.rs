use axum::{
    Form,
    extract::State,
    http::{HeaderMap, StatusCode},
    response::Response,
};
use serde::Deserialize;

use crate::{
    application::error::{AppError, kind::ErrorKind},
    boot::AppState,
};

#[derive(Debug, Deserialize)]
pub(crate) struct UserInfoForm {
    access_token: Option<String>,
}

#[axum::debug_handler]
pub async fn userinfo(State(ctx): State<AppState>, headers: HeaderMap) -> Response {
    let auth_header = headers.get("Authorization").and_then(|v| v.to_str().ok());

    let bearer_token = match auth_header {
        Some(header) if header.starts_with("Bearer ") => &header[7..],
        Some(_) => {
            return build_error_response(
                StatusCode::UNAUTHORIZED,
                "invalid_request",
                "Authorization header must use Bearer scheme",
            );
        }
        None => {
            return build_error_response(
                StatusCode::UNAUTHORIZED,
                "invalid_request",
                "Authorization header is required",
            );
        }
    };

    handle_userinfo_request(ctx, bearer_token).await
}

#[axum::debug_handler]
pub async fn userinfo_post(
    State(ctx): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<UserInfoForm>,
) -> Response {
    // Token may come from Authorization header or POST body
    let auth_header = headers.get("Authorization").and_then(|v| v.to_str().ok());

    let bearer_token: String = if let Some(header) = auth_header {
        if let Some(token) = header.strip_prefix("Bearer ") {
            token.to_string()
        } else {
            return build_error_response(
                StatusCode::UNAUTHORIZED,
                "invalid_request",
                "Authorization header must use Bearer scheme",
            );
        }
    } else if let Some(token) = form.access_token {
        token
    } else {
        return build_error_response(
            StatusCode::UNAUTHORIZED,
            "invalid_request",
            "Bearer token required in Authorization header or access_token parameter",
        );
    };

    handle_userinfo_request(ctx, &bearer_token).await
}

async fn handle_userinfo_request(ctx: AppState, token: &str) -> Response {
    let service = ctx.services().user_info();

    let token_claims = match service.validate_access_token(token).await {
        Ok(claims) => claims,
        Err(error) => return build_error_from_app_error(error),
    };

    let user_claims = match service
        .get_user_info(token_claims.user_oid, &token_claims.scope)
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
    Response::builder()
        .status(StatusCode::OK)
        .header("Content-Type", "application/json")
        .header("Cache-Control", "no-store, no-cache, must-revalidate")
        .header("Pragma", "no-cache")
        .body(serde_json::to_string(&claims).unwrap().into())
        .unwrap()
}

fn build_error_response(status: StatusCode, error_code: &str, error_description: &str) -> Response {
    let error_body = serde_json::json!({
        "error": error_code,
        "error_description": error_description
    });

    Response::builder()
        .status(status)
        .header("Content-Type", "application/json")
        .header("Cache-Control", "no-store")
        .header(
            "WWW-Authenticate",
            format!("Bearer error=\"{}\"", error_code),
        )
        .body(serde_json::to_string(&error_body).unwrap().into())
        .unwrap()
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
