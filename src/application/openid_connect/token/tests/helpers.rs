use super::*;

#[test]
fn verify_pkce_accepts_matching_s256_verifier() {
    let verifier = "abc123verifier";
    let digest = Sha256::digest(verifier.as_bytes());
    let challenge = URL_SAFE_NO_PAD.encode(digest);

    assert!(
        verify_pkce(
            Some(&challenge),
            Some("S256".parse().unwrap()),
            Some(verifier)
        )
        .is_ok()
    );
}

#[test]
fn verify_pkce_rejects_plain_even_when_verifier_matches() {
    let result = verify_pkce(
        Some("verifier"),
        Some("plain".parse().unwrap()),
        Some("verifier"),
    );
    assert_eq!(result.unwrap_err().code(), 24048);
}

#[test]
fn verify_pkce_rejects_implicit_plain_method() {
    let result = verify_pkce(Some("verifier"), None, Some("verifier"));
    assert_eq!(result.unwrap_err().code(), 24048);
}
