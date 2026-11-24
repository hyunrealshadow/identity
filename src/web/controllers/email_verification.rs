//! Email verification links, followed through the Login application.
//!
//! `POST /internal/email-verification` consumes the link token after the
//! user confirmed on the Login page. It needs no session: holding the link
//! proves control of the mailbox. Only Login's workload may call it.

use http::StatusCode;
use salvo::{Depot, Request, Response, Router, handler};
use serde::{Deserialize, Serialize};

use super::response::{JsonWebResult, app_state, parse_json, render_json};

pub fn routes() -> Router {
    Router::with_path("email-verification").post(confirm)
}

#[derive(Deserialize)]
struct ConfirmRequest {
    token: String,
}

#[derive(Serialize)]
struct ConfirmResponse {
    status: &'static str,
    email: String,
    /// Whether the account's address was replaced.
    changed: bool,
}

#[handler]
async fn confirm(depot: &mut Depot, req: &mut Request, res: &mut Response) -> JsonWebResult<()> {
    let ctx = app_state(depot)?;
    let body: ConfirmRequest = parse_json(req).await?;
    let verified = ctx
        .services()
        .account()
        .confirm_email_verification(&body.token)
        .await?;
    render_json(
        res,
        StatusCode::OK,
        ConfirmResponse {
            status: "verified",
            email: verified.email,
            changed: verified.changed,
        },
    );
    Ok(())
}
