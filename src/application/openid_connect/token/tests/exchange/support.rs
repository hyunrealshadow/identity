use serde_json::from_slice;

use super::*;

pub(super) fn decode_unverified_payload(token: &str) -> Value {
    let payload = token.split('.').nth(1).unwrap();
    from_slice(&URL_SAFE_NO_PAD.decode(payload).unwrap()).unwrap()
}

#[derive(Default)]
pub(super) struct RecordingSink {
    pub(super) events: Mutex<Vec<BusinessEvent>>,
}

impl RecordingSink {
    pub(super) fn names(&self) -> Vec<&'static str> {
        self.events
            .lock()
            .unwrap()
            .iter()
            .map(|event| event.name)
            .collect()
    }

    pub(super) fn outcome_of(&self, name: &str) -> Option<&'static str> {
        self.events
            .lock()
            .unwrap()
            .iter()
            .find(|event| event.name == name)
            .and_then(|event| event.outcome)
    }

    pub(super) fn assert_attribute(&self, name: &str, outcome: &str, key: &str, value: EventValue) {
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
