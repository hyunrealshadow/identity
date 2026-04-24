use super::*;

#[test]
fn verify_pkce_accepts_matching_s256_verifier() {
    let verifier = "abc123verifier";
    let digest = Sha256::digest(verifier.as_bytes());
    let challenge = URL_SAFE_NO_PAD.encode(digest);

    assert!(verify_pkce(Some(&challenge), Some("S256"), Some(verifier)).is_ok());
}

#[test]
fn verify_pkce_rejects_mismatched_plain_verifier() {
    let result = verify_pkce(Some("expected"), Some("plain"), Some("actual"));
    assert!(result.is_err());
}
