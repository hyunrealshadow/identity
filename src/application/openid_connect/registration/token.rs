use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use rand::RngExt;

pub(super) fn generate_client_secret() -> String {
    generate_url_safe_token()
}

pub(super) fn generate_registration_access_token() -> String {
    generate_url_safe_token()
}

fn generate_url_safe_token() -> String {
    let mut bytes = [0_u8; 32];
    rand::rng().fill(&mut bytes[..]);
    URL_SAFE_NO_PAD.encode(bytes)
}

pub(super) const fn default_skip_consent() -> bool {
    cfg!(feature = "oidc-conformance")
}
