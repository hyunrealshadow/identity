use fixtures::{
    DEVICE_USER_CODE, consent_test_config, consent_test_state, consent_test_state_with_scope,
    device_decision_test_state, device_verification_test_state, unknown_user_code_test_state,
};
use http::{StatusCode, header};
use salvo::{
    Service,
    test::{ResponseExt, TestClient},
};
use serde_json::Value;

use crate::router::app_router;

mod fixtures;

mod behavior;
