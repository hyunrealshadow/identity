use identity_domain::openid_connect::AuthorizationRequest;
use salvo::{Depot, Request, Response, handler, handler::HoopedHandler};

use super::{
    super::pipeline::{Endpoint, RequireState, get, take},
    interaction::{FlowDecision, determine_authorize_flow},
    request::{RawAuthorizeRequest, authorize_input_error, extract_authorize_request},
    response::{AuthorizationWebError, flow_response, render_authorize_error_page},
};
use crate::controllers::{
    response::{AppResponse, WebError, WebResult, app_state},
    shared::{ActiveSessionEntry, load_op_active_session_entries},
};

struct ValidatedAuthorization {
    request: AuthorizationRequest,
}

struct AuthorizationSessions(Vec<ActiveSessionEntry>);

struct AuthorizationInteraction {
    login_id: String,
}

pub fn endpoint() -> HoopedHandler {
    Endpoint::new("authorization")
        .action("state", RequireState::<WebError>::new())
        .action("parse_request", parse_request)
        .action("validate_request", validate_request)
        .action("load_sessions", load_sessions)
        .action("create_interaction", create_interaction)
        .action("select_interaction", select_interaction)
        .finish("respond", respond)
}

#[handler]
async fn parse_request(depot: &mut Depot, req: &mut Request, res: &mut Response) -> WebResult<()> {
    let ctx = app_state(depot)?;
    let raw = extract_authorize_request(req).await?;
    if let Some(error) = authorize_input_error(&raw) {
        *res = render_authorize_error_page(&ctx, req.headers(), error);
        return Ok(());
    }
    depot.insert_typed(raw);
    Ok(())
}

#[handler]
async fn validate_request(depot: &mut Depot) -> Result<(), AuthorizationWebError> {
    let ctx = app_state(depot)?;
    let raw = get::<RawAuthorizeRequest>(depot)?.clone();
    let (request, _) = ctx
        .services()
        .oidc_authorize()
        .validate_request(raw.clone().into())
        .await?;
    depot.insert_typed(RawAuthorizeRequest {
        response_type: Some(request.response_type.to_string()),
        response_mode: request.response_mode.map(|value| value.to_string()),
        client_id: Some(request.client_id.to_string()),
        redirect_uri: Some(request.redirect_uri_raw.clone()),
        scope: Some(request.scope.to_scope_string()),
        state: Some(request.state.clone()),
        ..raw
    });
    depot.insert_typed(ValidatedAuthorization { request });
    Ok(())
}

#[handler]
async fn load_sessions(depot: &mut Depot, req: &mut Request) -> Result<(), AuthorizationWebError> {
    let ctx = app_state(depot)?;
    let entries = load_op_active_session_entries(&ctx, req.headers()).await?;
    depot.insert_typed(AuthorizationSessions(entries));
    Ok(())
}

#[handler]
async fn create_interaction(depot: &mut Depot) -> Result<(), AuthorizationWebError> {
    let ctx = app_state(depot)?;
    let request = &get::<ValidatedAuthorization>(depot)?.request;
    let service = ctx.services().oidc_authorize();
    let request_id = service.create_authorization_request(request).await?;
    let login_id = service
        .create_login_flow(
            request.client_id,
            request_id,
            request
                .acr_values
                .as_ref()
                .and_then(|values| values.first())
                .map(String::as_str),
        )
        .await?;
    depot.insert_typed(AuthorizationInteraction { login_id });
    Ok(())
}

#[handler]
async fn select_interaction(depot: &mut Depot) -> Result<(), AuthorizationWebError> {
    let ctx = app_state(depot)?;
    let validated: ValidatedAuthorization = take(depot)?;
    let entries = take::<AuthorizationSessions>(depot)?.0;
    let active_sessions = entries
        .iter()
        .map(|entry| entry.session.clone())
        .collect::<Vec<_>>();
    let protected_session_ids = entries
        .iter()
        .map(|entry| {
            (
                entry.session.session_oid,
                entry.protected_session_id.clone(),
            )
        })
        .collect();
    let interaction: AuthorizationInteraction = take(depot)?;
    let flow = determine_authorize_flow(
        &validated.request,
        &active_sessions,
        &protected_session_ids,
        interaction.login_id,
        ctx.services().oidc_authorize(),
    )
    .await?;
    depot.insert_typed(flow);
    Ok(())
}

#[handler]
async fn respond(depot: &mut Depot, req: &mut Request) -> WebResult {
    let ctx = app_state(depot)?;
    let flow: FlowDecision = take(depot)?;
    Ok(AppResponse(flow_response(flow, &ctx, req.headers())?))
}
