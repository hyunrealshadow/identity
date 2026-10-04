mod authorization_code;
mod client_credentials;
mod device_code;
mod grant_permissions;
mod refresh_token;

mod custom_scopes;
mod resources;

use crate::observability::{BusinessEvent, EventSink, EventValue};

fn decode_unverified_payload(token: &str) -> serde_json::Value {
    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
    let payload = token.split('.').nth(1).unwrap();
    serde_json::from_slice(&URL_SAFE_NO_PAD.decode(payload).unwrap()).unwrap()
}

#[derive(Default)]
struct RecordingSink {
    events: std::sync::Mutex<Vec<BusinessEvent>>,
}

impl RecordingSink {
    fn names(&self) -> Vec<&'static str> {
        self.events
            .lock()
            .unwrap()
            .iter()
            .map(|event| event.name)
            .collect()
    }

    fn outcome_of(&self, name: &str) -> Option<&'static str> {
        self.events
            .lock()
            .unwrap()
            .iter()
            .find(|event| event.name == name)
            .and_then(|event| event.outcome)
    }

    fn assert_attribute(&self, name: &str, outcome: &str, key: &str, value: EventValue) {
        let events = self.events.lock().unwrap();
        let event = events
            .iter()
            .find(|event| event.name == name && event.outcome == Some(outcome))
            .unwrap();
        assert!(
            event
                .attributes
                .iter()
                .any(|(field, actual)| *field == key && *actual == value),
            "missing {key} in {event:?}"
        );
    }
}

impl EventSink for RecordingSink {
    fn emit(&self, event: BusinessEvent) {
        self.events.lock().unwrap().push(event);
    }
}
