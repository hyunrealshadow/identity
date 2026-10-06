use std::sync::Mutex;

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use serde_json::Value;

use crate::observability::{BusinessEvent, EventSink, EventValue};

use support::*;

mod authorization_code;
mod client_credentials;
mod device_code;
mod grant_permissions;
mod refresh_token;

mod custom_scopes;
mod resources;

mod support;
