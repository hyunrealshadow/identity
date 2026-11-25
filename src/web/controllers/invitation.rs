//! Invitations, accepted through the Login application.
//!
//! `POST /internal/invitation/check` shows the account of a link without
//! using it, and `POST /internal/invitation/accept` sets its first password
//! after the user submitted it on the Login page. Neither needs a session:
//! holding the link proves control of the mailbox. Only Login's workload may
//! call them.

use http::StatusCode;
use salvo::{Depot, Request, Response, Router, handler};
use serde::{Deserialize, Serialize};

use super::response::{JsonWebResult, app_state, parse_json, render_json};

pub fn routes() -> Router {
    Router::with_path("invitation")
        .push(Router::with_path("check").post(check))
        .push(Router::with_path("accept").post(accept))
}

#[derive(Deserialize)]
struct CheckRequest {
    token: String,
}

#[derive(Serialize)]
struct CheckResponse {
    status: &'static str,
    username: String,
    email: String,
}

/// Not `Debug`: it carries the new password.
#[derive(Deserialize)]
struct AcceptRequest {
    token: String,
    new_password: String,
}

#[derive(Serialize)]
struct AcceptResponse {
    status: &'static str,
}

#[handler]
async fn check(depot: &mut Depot, req: &mut Request, res: &mut Response) -> JsonWebResult<()> {
    let ctx = app_state(depot)?;
    let body: CheckRequest = parse_json(req).await?;
    let account = ctx.services().invitation().check(&body.token).await?;
    render_json(
        res,
        StatusCode::OK,
        CheckResponse {
            status: "valid",
            username: account.username,
            email: account.email,
        },
    );
    Ok(())
}

#[handler]
async fn accept(depot: &mut Depot, req: &mut Request, res: &mut Response) -> JsonWebResult<()> {
    let ctx = app_state(depot)?;
    let body: AcceptRequest = parse_json(req).await?;
    ctx.services()
        .invitation()
        .accept(&body.token, &body.new_password)
        .await?;
    render_json(res, StatusCode::OK, AcceptResponse { status: "accepted" });
    Ok(())
}
