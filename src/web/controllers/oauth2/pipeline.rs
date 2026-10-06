//! Endpoint-local action chains, assembled once when the routes are loaded.
//!
//! Like oidc-provider's action loaders, each endpoint declares its ordered
//! actions. Salvo owns continuation and short-circuiting; a protocol error or
//! redirect stops the remaining actions. Typed Depot entries carry requests
//! between actions without mixing different endpoints' state.
//!
//! Declare each chain in its endpoint module, with transport extractors first
//! and the response action last. Wire the returned handler below the route's
//! CORS/CSRF hoops; OPTIONS remains a separate handler. Domain authentication
//! and persistence stay in application services. Action spans record only
//! endpoint and action names, never credentials or request payloads.
//!
//! Reference: <https://github.com/panva/node-oidc-provider/blob/main/lib/actions/authorization/index.js>

use std::marker::PhantomData;

use identity_application::error::{AppError, codes::common::CommonErrorCode};
use salvo::{
    Depot, FlowCtrl, Handler, Request, Response, Writer, async_trait,
    handler::{ArcHandler, HoopedHandler},
};
use serde::de::DeserializeOwned;
use tracing::{Instrument, info_span};

use crate::controllers::response::{app_state, parse_form, parse_json, parse_query};

pub(super) struct Endpoint {
    name: &'static str,
    actions: Vec<ArcHandler>,
}

impl Endpoint {
    pub fn new(name: &'static str) -> Self {
        Self {
            name,
            actions: Vec::new(),
        }
    }

    pub fn action(mut self, name: &'static str, handler: impl Handler) -> Self {
        self.actions.push(
            Action {
                endpoint: self.name,
                name,
                handler,
            }
            .arc(),
        );
        self
    }

    pub fn finish(self, name: &'static str, handler: impl Handler) -> HoopedHandler {
        let mut chain = HoopedHandler::new(Action {
            endpoint: self.name,
            name,
            handler,
        });
        for action in self.actions {
            chain = chain.hoop(action);
        }
        chain
    }
}

struct Action<H> {
    endpoint: &'static str,
    name: &'static str,
    handler: H,
}

#[async_trait]
impl<H: Handler> Handler for Action<H> {
    async fn handle(
        &self,
        req: &mut Request,
        depot: &mut Depot,
        res: &mut Response,
        ctrl: &mut FlowCtrl,
    ) {
        self.handler
            .handle(req, depot, res, ctrl)
            .instrument(info_span!(
                "oidc.action",
                endpoint = self.endpoint,
                action = self.name
            ))
            .await;
    }
}

fn missing_input() -> AppError {
    AppError::from_code(CommonErrorCode::InternalError)
        .with_param("message", "Protocol action input is missing")
}

pub(super) fn take<T: Send + Sync + 'static>(depot: &mut Depot) -> Result<T, AppError> {
    depot.remove_typed::<T>().map_err(|_| missing_input())
}

pub(super) fn get<T: Send + Sync + 'static>(depot: &Depot) -> Result<&T, AppError> {
    depot.get_typed::<T>().map_err(|_| missing_input())
}

pub(super) struct RequireState<E>(PhantomData<fn() -> E>);

impl<E> RequireState<E> {
    pub fn new() -> Self {
        Self(PhantomData)
    }
}

#[async_trait]
impl<E: From<AppError> + Writer + Send + 'static> Handler for RequireState<E> {
    async fn handle(
        &self,
        req: &mut Request,
        depot: &mut Depot,
        res: &mut Response,
        ctrl: &mut FlowCtrl,
    ) {
        if let Err(error) = app_state(depot) {
            E::from(error).write(req, depot, res).await;
            ctrl.skip_rest();
        }
    }
}

enum Input {
    Form,
    Query,
    Json,
}

pub(super) struct Extract<T, E> {
    input: Input,
    marker: PhantomData<fn() -> (T, E)>,
}

impl<T, E> Extract<T, E> {
    pub fn form() -> Self {
        Self::new(Input::Form)
    }
    pub fn query() -> Self {
        Self::new(Input::Query)
    }
    pub fn json() -> Self {
        Self::new(Input::Json)
    }
    fn new(input: Input) -> Self {
        Self {
            input,
            marker: PhantomData,
        }
    }
}

#[async_trait]
impl<T, E> Handler for Extract<T, E>
where
    T: DeserializeOwned + Send + Sync + 'static,
    E: From<AppError> + Writer + Send + 'static,
{
    async fn handle(
        &self,
        req: &mut Request,
        depot: &mut Depot,
        res: &mut Response,
        ctrl: &mut FlowCtrl,
    ) {
        let input = match self.input {
            Input::Form => parse_form::<T>(req).await,
            Input::Query => parse_query::<T>(req),
            Input::Json => parse_json::<T>(req).await,
        };
        match input {
            Ok(input) => {
                depot.insert_typed(input);
            }
            Err(error) => {
                E::from(error).write(req, depot, res).await;
                ctrl.skip_rest();
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use http::{StatusCode, header};
    use salvo::{
        Router, Service,
        affix_state::inject,
        handler,
        test::{ResponseExt, TestClient},
    };
    use serde::Deserialize;
    use serde_json::{Value, from_str};

    use crate::controllers::{oauth2::token::TokenWebError, response::json_response};

    use super::*;

    type Trace = Arc<Mutex<Vec<&'static str>>>;

    struct Record(&'static str);

    #[async_trait]
    impl Handler for Record {
        async fn handle(
            &self,
            _req: &mut Request,
            depot: &mut Depot,
            _res: &mut Response,
            _ctrl: &mut FlowCtrl,
        ) {
            depot
                .get_typed::<Trace>()
                .unwrap()
                .lock()
                .unwrap()
                .push(self.0);
        }
    }

    struct Stop(StatusCode);

    #[async_trait]
    impl Handler for Stop {
        async fn handle(
            &self,
            _req: &mut Request,
            depot: &mut Depot,
            res: &mut Response,
            _ctrl: &mut FlowCtrl,
        ) {
            depot
                .get_typed::<Trace>()
                .unwrap()
                .lock()
                .unwrap()
                .push("stop");
            res.status_code(self.0);
        }
    }

    #[tokio::test]
    async fn actions_run_in_order_and_stop_before_side_effects_on_error_or_redirect() {
        for status in [
            StatusCode::OK,
            StatusCode::BAD_REQUEST,
            StatusCode::SEE_OTHER,
        ] {
            let trace: Trace = Arc::default();
            let chain = Endpoint::new("test")
                .action("parse", Record("parse"))
                .action("validate", Stop(status))
                .action("persist", Record("persist"))
                .finish("respond", Record("respond"));
            let service = Service::new(Router::new().hoop(inject(trace.clone())).get(chain));
            let response = TestClient::get("http://localhost/").send(&service).await;
            assert_eq!(response.status_code, Some(status));
            if status == StatusCode::OK {
                assert_eq!(
                    *trace.lock().unwrap(),
                    ["parse", "stop", "persist", "respond"]
                );
            } else {
                assert_eq!(*trace.lock().unwrap(), ["parse", "stop"]);
            }
        }
    }

    #[derive(Deserialize)]
    struct InputValue {
        value: u32,
    }

    #[handler]
    async fn increment(depot: &mut Depot, res: &mut Response) -> Result<(), TokenWebError> {
        let input: InputValue = take(depot)?;
        *res = json_response(StatusCode::OK, input.value + 1);
        Ok(())
    }

    #[tokio::test]
    async fn reusable_chain_keeps_request_input_isolated_and_uses_protocol_errors() {
        let chain = Endpoint::new("test")
            .action("parse", Extract::<InputValue, TokenWebError>::form())
            .finish("increment", increment);
        let service = Service::new(Router::new().post(chain));
        for (body, expected) in [("value=1", "2"), ("value=40", "41")] {
            let mut response = TestClient::post("http://localhost/")
                .add_header(
                    header::CONTENT_TYPE,
                    "application/x-www-form-urlencoded",
                    true,
                )
                .body(body)
                .send(&service)
                .await;
            assert_eq!(response.status_code, Some(StatusCode::OK));
            assert_eq!(response.take_string().await.unwrap(), expected);
        }
        let mut response = TestClient::post("http://localhost/")
            .add_header(
                header::CONTENT_TYPE,
                "application/x-www-form-urlencoded",
                true,
            )
            .add_header(header::ACCEPT, "text/html", true)
            .body("value=bad")
            .send(&service)
            .await;
        assert_eq!(response.status_code, Some(StatusCode::BAD_REQUEST));
        assert_eq!(
            response.headers().get(header::CACHE_CONTROL).unwrap(),
            "no-store"
        );
        let body: Value = from_str(&response.take_string().await.unwrap()).unwrap();
        assert_eq!(body["error"], "invalid_request");
    }
}
