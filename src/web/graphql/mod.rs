mod cursor;
mod id;
mod schema;
#[cfg(test)]
mod tests;

use async_graphql::{
    Request as GraphqlRequest,
    http::{GraphiQLSource, parse_query_string},
    parser::{parse_query, types::OperationType},
};
use http::{HeaderValue, Method, StatusCode, header};
use identity_domain::user::repository::UserRepository;
use identity_infrastructure::{
    AppState,
    config::{GraphqlConfig, ServerConfig},
    database::repository::user::UserRepositoryImpl,
};
use salvo::{Depot, Request, Response, Router, handler, writing::Text};

use self::schema::{ApiSchema, RESOURCE_AUDIENCE, RequestContext, build_schema};

const MAX_BODY_BYTES: usize = 256 * 1024;
const MAX_URI_BYTES: usize = 16 * 1024;

pub fn router(state: AppState, config: &GraphqlConfig) -> Router {
    let schema = build_schema(config.max_depth, config.max_complexity);
    Router::with_path("graphql")
        .hoop(crate::middleware::security_headers_middleware)
        .hoop(salvo::affix_state::inject(state))
        .hoop(salvo::affix_state::inject(config.clone()))
        .hoop(salvo::affix_state::inject(schema))
        .options(graphql_options)
        .get(graphql_handler)
        .post(graphql_handler)
}

#[handler]
async fn graphql_options(depot: &mut Depot, req: &mut Request, res: &mut Response) {
    let Ok(config) = depot.obtain::<GraphqlConfig>() else {
        res.status_code(StatusCode::INTERNAL_SERVER_ERROR);
        return;
    };
    if apply_cors(req, res, config) {
        res.headers_mut().insert(
            header::ACCESS_CONTROL_ALLOW_METHODS,
            HeaderValue::from_static("GET, POST, OPTIONS"),
        );
        res.headers_mut().insert(
            header::ACCESS_CONTROL_ALLOW_HEADERS,
            HeaderValue::from_static("authorization, content-type"),
        );
        res.status_code(StatusCode::NO_CONTENT);
    } else {
        res.status_code(StatusCode::FORBIDDEN);
    }
}

#[handler]
async fn graphql_handler(depot: &mut Depot, req: &mut Request, res: &mut Response) {
    set_graphql_response_headers(res);
    let Ok(state) = crate::controllers::response::app_state(depot) else {
        write_protocol_error(
            res,
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal server error",
        );
        return;
    };
    let Ok(config) = depot.obtain::<GraphqlConfig>() else {
        write_protocol_error(
            res,
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal server error",
        );
        return;
    };
    if req.uri().to_string().len() > MAX_URI_BYTES {
        write_protocol_error(res, StatusCode::URI_TOO_LONG, "request URI is too long");
        return;
    }
    if req.headers().contains_key(header::ORIGIN) && !apply_cors(req, res, config) {
        write_protocol_error(res, StatusCode::FORBIDDEN, "origin is not allowed");
        return;
    }

    let has_query = req.uri().query().is_some_and(|query| {
        url::form_urlencoded::parse(query.as_bytes()).any(|(key, _)| key == "query")
    });
    if req.method() == Method::GET
        && !has_query
        && !state.context().environment().is_production()
        && crate::controllers::response::accepts_html(req.headers())
    {
        res.headers_mut().insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static("text/html; charset=utf-8"),
        );
        res.render(Text::Html(
            GraphiQLSource::build().endpoint("/graphql").finish(),
        ));
        return;
    }

    let graphql_request = match parse_graphql_request(req).await {
        Ok(request) => request,
        Err((status, message)) => {
            write_protocol_error(res, status, message);
            return;
        }
    };
    if req.method() == Method::GET && is_mutation(&graphql_request) {
        res.headers_mut()
            .insert(header::ALLOW, HeaderValue::from_static("POST"));
        write_protocol_error(
            res,
            StatusCode::METHOD_NOT_ALLOWED,
            "mutations require POST",
        );
        return;
    }

    let Some(token) = bearer_token(req) else {
        write_unauthorized(res, "Bearer access token is required");
        return;
    };
    let claims = match state
        .services()
        .user_info()
        .validate_access_token(token)
        .await
    {
        Ok(claims) if claims.audience.iter().any(|aud| aud == RESOURCE_AUDIENCE) => claims,
        _ => {
            write_unauthorized(res, "invalid access token");
            return;
        }
    };
    let user_repo = UserRepositoryImpl::new(state.resources().db().clone());
    let user = match user_repo.find_by_oid(claims.user_oid).await {
        Ok(Some(user)) if user.enabled && !user.locked => user,
        _ => {
            write_unauthorized(res, "invalid access token");
            return;
        }
    };

    let Some(schema) = depot.obtain::<ApiSchema>().ok().cloned() else {
        write_protocol_error(
            res,
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal server error",
        );
        return;
    };
    let request = graphql_request
        .data(RequestContext {
            state,
            claims,
            user,
            locale: crate::infrastructure::i18n::resolve_locale_from_headers(req.headers()),
            request_id: req
                .headers()
                .get("x-request-id")
                .and_then(|value| value.to_str().ok())
                .map(str::to_owned)
                .unwrap_or_else(|| uuid::Uuid::new_v4().to_string()),
        })
        .data(config.max_page_size);
    let response = match tokio::time::timeout(
        std::time::Duration::from_secs(config.timeout_secs),
        schema.execute(request),
    )
    .await
    {
        Ok(response) => response,
        Err(_) => {
            write_protocol_error(res, StatusCode::GATEWAY_TIMEOUT, "request timed out");
            return;
        }
    };
    res.status_code(StatusCode::OK);
    res.render(salvo::prelude::Json(response));
}

async fn parse_graphql_request(
    req: &mut Request,
) -> Result<GraphqlRequest, (StatusCode, &'static str)> {
    match *req.method() {
        Method::GET => parse_query_string(req.uri().query().unwrap_or_default())
            .map_err(|_| (StatusCode::BAD_REQUEST, "invalid GraphQL request")),
        Method::POST => {
            let content_type = req
                .headers()
                .get(header::CONTENT_TYPE)
                .and_then(|value| value.to_str().ok())
                .unwrap_or_default();
            if !content_type
                .split(';')
                .next()
                .is_some_and(|value| value.trim().eq_ignore_ascii_case("application/json"))
            {
                return Err((
                    StatusCode::UNSUPPORTED_MEDIA_TYPE,
                    "content type must be application/json",
                ));
            }
            let payload = req
                .payload_with_max_size(MAX_BODY_BYTES)
                .await
                .map_err(|_| (StatusCode::PAYLOAD_TOO_LARGE, "request body is too large"))?;
            serde_json::from_slice(payload)
                .map_err(|_| (StatusCode::BAD_REQUEST, "invalid GraphQL request"))
        }
        _ => Err((StatusCode::METHOD_NOT_ALLOWED, "method not allowed")),
    }
}

fn is_mutation(request: &GraphqlRequest) -> bool {
    let Ok(document) = parse_query(&request.query) else {
        return false;
    };
    document.operations.iter().any(|(name, operation)| {
        operation.node.ty == OperationType::Mutation
            && request
                .operation_name
                .as_deref()
                .is_none_or(|selected| name.is_some_and(|name| name.as_str() == selected))
    })
}

fn bearer_token(req: &Request) -> Option<&str> {
    let value = req.headers().get(header::AUTHORIZATION)?.to_str().ok()?;
    let (scheme, token) = value.split_once(' ')?;
    (scheme.eq_ignore_ascii_case("Bearer") && !token.trim().is_empty()).then_some(token.trim())
}

fn apply_cors(req: &Request, res: &mut Response, config: &GraphqlConfig) -> bool {
    let Some(origin) = req
        .headers()
        .get(header::ORIGIN)
        .and_then(|value| value.to_str().ok())
    else {
        return true;
    };
    if !config
        .allowed_origins
        .iter()
        .any(|allowed| allowed == origin)
    {
        return false;
    }
    if let Ok(value) = HeaderValue::from_str(origin) {
        res.headers_mut()
            .insert(header::ACCESS_CONTROL_ALLOW_ORIGIN, value);
        res.headers_mut()
            .insert(header::VARY, HeaderValue::from_static("Origin"));
    }
    true
}

fn set_graphql_response_headers(res: &mut Response) {
    res.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/graphql-response+json; charset=utf-8"),
    );
    crate::controllers::response::insert_no_store_headers(res);
}

fn write_unauthorized(res: &mut Response, message: &'static str) {
    res.headers_mut().insert(
        header::WWW_AUTHENTICATE,
        HeaderValue::from_static("Bearer realm=\"graphql\", error=\"invalid_token\""),
    );
    write_protocol_error(res, StatusCode::UNAUTHORIZED, message);
}

fn write_protocol_error(res: &mut Response, status: StatusCode, message: &'static str) {
    res.status_code(status);
    res.render(salvo::prelude::Json(serde_json::json!({
        "errors": [{ "message": message }]
    })));
}

pub fn bind_address(graphql: &GraphqlConfig, server: &ServerConfig) -> String {
    let binding = graphql
        .server
        .binding
        .as_deref()
        .unwrap_or(server.binding.as_str());
    let port = graphql.server.port.unwrap_or(server.port);
    format!("{binding}:{port}")
}

pub fn shares_listener(graphql: &GraphqlConfig, server: &ServerConfig) -> bool {
    bind_address(graphql, server) == format!("{}:{}", server.binding, server.port)
}

#[cfg(test)]
mod unit_tests {
    use async_graphql::Request as GraphqlRequest;
    use identity_infrastructure::config::{GraphqlConfig, GraphqlServerConfig, ServerConfig};

    use super::{bind_address, is_mutation, shares_listener};

    #[test]
    fn graphql_listener_inherits_main_address_by_default() {
        let server = ServerConfig::default();
        let graphql = GraphqlConfig::default();

        assert_eq!(
            bind_address(&graphql, &server),
            format!("{}:{}", server.binding, server.port)
        );
        assert!(shares_listener(&graphql, &server));
    }

    #[test]
    fn graphql_listener_can_use_an_independent_port() {
        let server = ServerConfig::default();
        let graphql = GraphqlConfig {
            server: GraphqlServerConfig {
                binding: Some("127.0.0.1".to_string()),
                port: Some(9443),
            },
            ..Default::default()
        };

        assert_eq!(bind_address(&graphql, &server), "127.0.0.1:9443");
        assert!(!shares_listener(&graphql, &server));
    }

    #[test]
    fn identifies_get_mutation_operations() {
        assert!(is_mutation(&GraphqlRequest::new(
            "mutation Revoke { revokeSession(id: \"x\") { clientMutationId } }",
        )));
        assert!(!is_mutation(&GraphqlRequest::new(
            "query Viewer { viewer { account { id } } }",
        )));
    }
}
