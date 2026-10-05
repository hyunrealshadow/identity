use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use sha2::{Digest, Sha256};

pub fn calculate_session_state(
    client_id: &str,
    origin: &str,
    op_browser_state: &str,
    salt: &str,
) -> String {
    let mut hasher = Sha256::new();
    hasher.update(client_id);
    hasher.update(b" ");
    hasher.update(origin);
    hasher.update(b" ");
    hasher.update(op_browser_state);
    hasher.update(b" ");
    hasher.update(salt);

    format!("{}.{}", URL_SAFE_NO_PAD.encode(hasher.finalize()), salt)
}

#[cfg(test)]
mod tests {
    use super::calculate_session_state;

    #[test]
    fn calculate_session_state_is_deterministic_and_space_free() {
        let state =
            calculate_session_state("client-1", "https://rp.example.com", "session-a", "salt");

        assert_eq!(
            state,
            calculate_session_state("client-1", "https://rp.example.com", "session-a", "salt",)
        );
        assert!(!state.contains(' '));
        assert!(state.ends_with(".salt"));
    }

    #[test]
    fn calculate_session_state_changes_with_browser_state() {
        let first =
            calculate_session_state("client-1", "https://rp.example.com", "session-a", "salt");
        let second =
            calculate_session_state("client-1", "https://rp.example.com", "session-b", "salt");

        assert_ne!(first, second);
    }
}
