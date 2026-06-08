use http::{StatusCode, header};
use salvo::{Depot, Request, Response, handler};

use identity_application::{
    error::{AppError, code::AppErrorCode, codes::registration::RegistrationErrorCode},
    openid_connect::registration::DynamicClientRegistrationRequest,
};

use crate::controllers::response::{
    WebResult, app_state, insert_no_store_headers, parse_json, parse_param, render_json,
};

#[handler]
pub async fn register(depot: &mut Depot, req: &mut Request, res: &mut Response) -> WebResult<()> {
    let ctx = app_state(depot)?;
    let request: DynamicClientRegistrationRequest = parse_json(req).await?;
    let response = match ctx
        .services()
        .dynamic_client_registration()
        .register(request, &ctx.services().oidc().issuer()?)
        .await
    {
        Ok(response) => response,
        Err(error)
            if error.code() == RegistrationErrorCode::InvalidRedirectUri.code()
                || error.code() == RegistrationErrorCode::InvalidClientMetadata.code() =>
        {
            let (error_code, error_description) =
                if error.code() == RegistrationErrorCode::InvalidRedirectUri.code() {
                    (
                        "invalid_redirect_uri",
                        "redirect_uris must not contain fragments",
                    )
                } else {
                    ("invalid_client_metadata", "client metadata is invalid")
                };
            render_json(
                res,
                StatusCode::BAD_REQUEST,
                serde_json::json!({
                    "error": error_code,
                    "error_description": error_description
                }),
            );
            return Ok(());
        }
        Err(error) => return Err(error.into()),
    };

    insert_no_store_headers(res);
    render_json(res, StatusCode::CREATED, response);
    Ok(())
}

#[handler]
pub async fn read(depot: &mut Depot, req: &mut Request, res: &mut Response) -> WebResult<()> {
    let ctx = app_state(depot)?;
    let client_id: String = parse_param(req, "client_id")?;
    let registration_access_token = bearer_token(req)?;
    let response = ctx
        .services()
        .dynamic_client_registration()
        .read(
            &client_id,
            registration_access_token,
            &ctx.services().oidc().issuer()?,
        )
        .await?;

    insert_no_store_headers(res);
    render_json(res, StatusCode::OK, response);
    Ok(())
}

#[handler]
pub async fn delete(depot: &mut Depot, req: &mut Request, res: &mut Response) -> WebResult<()> {
    let ctx = app_state(depot)?;
    let client_id: String = parse_param(req, "client_id")?;
    let registration_access_token = bearer_token(req)?;
    ctx.services()
        .dynamic_client_registration()
        .delete(&client_id, registration_access_token)
        .await?;

    insert_no_store_headers(res);
    render_json(res, StatusCode::NO_CONTENT, ());
    Ok(())
}

fn bearer_token(req: &Request) -> Result<&str, AppError> {
    req.headers()
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            AppError::from_code(
                identity_application::error::codes::registration::RegistrationErrorCode::InvalidRegistrationAccessToken,
            )
        })
}
