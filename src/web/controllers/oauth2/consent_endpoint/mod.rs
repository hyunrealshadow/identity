use salvo::{Depot, Request, handler};
use serde::Deserialize;

use crate::{
    application::error::{AppError, codes::authorize_http::AuthorizeHttpErrorCode},
    web::controllers::response::WebResult,
};

mod api;
mod context;
mod decision;
mod device;

#[cfg(test)]
mod tests;

/// Identifies the interaction the consent UI is answering: a browser
/// authorization request (`login_id`) or a device request (`user_code`).
#[derive(Debug, Deserialize)]
struct ConsentQuery {
    login_id: Option<String>,
    user_code: Option<String>,
}

impl ConsentQuery {
    /// `Some(user_code)` for a device interaction, `None` for a browser
    /// authorization request. Anything else (both identifiers or neither) is
    /// rejected: the interaction must be unambiguous.
    fn device_target(&self) -> Result<Option<&str>, AppError> {
        match (self.login_id.as_deref(), self.user_code.as_deref()) {
            (Some(_), None) => Ok(None),
            (None, Some(user_code)) => Ok(Some(user_code)),
            _ => Err(AppError::from_code(
                AuthorizeHttpErrorCode::ContinueInteractionUnavailable,
            )),
        }
    }
}

#[handler]
pub async fn consent_get(depot: &mut Depot, req: &mut Request) -> WebResult {
    Ok(api::consent_api(depot, req).await?)
}

#[handler]
pub async fn consent_post(depot: &mut Depot, req: &mut Request) -> WebResult {
    Ok(api::consent_api_submit(depot, req).await?)
}
