use chrono::{Duration, Utc};
use fixtures::{
    ContinueFixture, continue_selected_session_state, continue_selected_session_with_consent_state,
    continue_selected_session_with_fixture, continue_selected_session_with_prompt_state,
    continue_state, continue_test_state,
};
use http::{StatusCode, header};
use identity_domain::client_authorization::ConsentState;
use identity_infrastructure::AppState;
use salvo::{Response, Service, affix_state::inject, test::TestClient};
use url::Url;
use uuid::Uuid;

use crate::controllers::oauth2::routes;

mod fixtures;

mod behavior;
