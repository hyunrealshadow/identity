use http::StatusCode;
use salvo::{Service, test::TestClient};

use identity_web::controllers::conformance::routes;

#[tokio::test]
async fn authentication_bypass_routes_are_not_exposed() {
    let service = Service::new(routes());
    for route in ["auto-login", "auto-consent"] {
        let url = format!("http://127.0.0.1:5800/conformance/{route}");
        let get = TestClient::get(&url).send(&service).await;
        let post = TestClient::post(&url).send(&service).await;
        assert_eq!(get.status_code, Some(StatusCode::NOT_FOUND));
        assert_eq!(post.status_code, Some(StatusCode::NOT_FOUND));
    }
}
