use http::{HeaderValue, StatusCode, header};
use salvo::{Depot, Request, Response, handler, writing::Text};
use serde::Deserialize;

use crate::controllers::response::{AppResponse, app_state, json_response, parse_form};
use crate::{
    application::error::{AppError, kind::ErrorKind},
    boot::AppState,
};

#[derive(Debug, Deserialize)]
struct UserInfoForm {
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

    // Check if client requires encrypted UserInfo response
    if let Some(encrypted) = try_encrypt_userinfo(&ctx, &token_claims, &user_claims).await {
        return encrypted;
    }

    build_success_response(user_claims)
}

async fn try_encrypt_userinfo(
    ctx: &AppState,
    token_claims: &identity_application::openid_connect::user_info::TokenClaims,
    user_claims: &identity_application::openid_connect::dto::UserInfoClaims,
) -> Option<Response> {
    use josekit::jwe::{JweEncrypter, JweHeader, RSA_OAEP, RSA_OAEP_256, ECDH_ES, ECDH_ES_A128KW, ECDH_ES_A256KW};
    use josekit::jwk::Jwk;

    // Load the client to check encryption metadata
    let client = ctx
        .services()
        .oidc_client_repo()
        .find_by_oid(token_claims.client_oid)
        .await
        .ok()??;

    let alg = client.metadata().userinfo_encrypted_response_alg.as_deref()?;
    let enc = client
        .metadata()
        .userinfo_encrypted_response_enc
        .as_deref()
        .unwrap_or("A128CBC-HS256");

    // Get the client's encryption key
    let credential = ctx
        .services()
        .oidc_credential_repo()
        .find_first_encryption_key(client.client().oid)
        .await
        .ok()??;

    let public_jwk = match &credential.data {
        identity_domain::openid_connect::OpenIdConnectCredentialData::ClientPublicKey {
            jwk: Some(jwk),
            ..
        } => jwk.clone(),
        _ => return None,
    };

    // Build the JWE encrypter from the client's JWK
    let jwk_value = serde_json::to_value(&public_jwk).ok()?;
    let jwk_json = jwk_value.to_string();
    let josekit_jwk = Jwk::from_bytes(jwk_json.as_bytes()).ok()?;

    let encrypter: Box<dyn JweEncrypter> = match alg {
        "RSA-OAEP" => Box::new(RSA_OAEP.encrypter_from_jwk(&josekit_jwk).ok()?),
        "RSA-OAEP-256" => Box::new(RSA_OAEP_256.encrypter_from_jwk(&josekit_jwk).ok()?),
        "ECDH-ES" => Box::new(ECDH_ES.encrypter_from_jwk(&josekit_jwk).ok()?),
        "ECDH-ES+A128KW" => Box::new(ECDH_ES_A128KW.encrypter_from_jwk(&josekit_jwk).ok()?),
        "ECDH-ES+A256KW" => Box::new(ECDH_ES_A256KW.encrypter_from_jwk(&josekit_jwk).ok()?),
        _ => return None,
    };

    let json_body = serde_json::to_string(user_claims).ok()?;

    let mut header = JweHeader::new();
    header.set_algorithm(alg);
    header.set_content_encryption(enc);

    let encrypted = josekit::jwe::serialize_compact(json_body.as_bytes(), &header, &*encrypter).ok()?;

    let mut response = Response::new();
    response.status_code(StatusCode::OK);
    response.render(Text::Plain(encrypted));
    response.headers_mut().insert(
        http::header::CONTENT_TYPE,
        http::HeaderValue::from_static("application/jose"),
    );
    response.headers_mut().insert(
        http::header::CACHE_CONTROL,
        http::HeaderValue::from_static("no-store"),
    );
    Some(response)
}

fn build_success_response(
    claims: identity_application::openid_connect::dto::UserInfoClaims,
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
