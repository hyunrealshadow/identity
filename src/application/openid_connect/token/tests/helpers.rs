use super::*;
use identity_domain::openid_connect::OAuthProtocolVersion;

#[test]
fn verify_pkce_accepts_matching_s256_verifier() {
    let verifier = "abc123verifier";
    let digest = Sha256::digest(verifier.as_bytes());
    let challenge = URL_SAFE_NO_PAD.encode(digest);

    assert!(
        verify_pkce(
            Some(&challenge),
            Some("S256".parse().unwrap()),
            Some(verifier),
            OAuthProtocolVersion::V2_1,
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
        OAuthProtocolVersion::V2_1,
    );
    assert_eq!(result.unwrap_err().code(), 24048);
}

#[test]
fn verify_pkce_rejects_implicit_plain_method() {
    let result = verify_pkce(
        Some("verifier"),
        None,
        Some("verifier"),
        OAuthProtocolVersion::V2_1,
    );
    assert_eq!(result.unwrap_err().code(), 24048);
}

#[test]
fn verify_pkce_rejects_verifier_when_authorization_had_no_challenge() {
    assert_eq!(
        verify_pkce(None, None, Some("verifier"), OAuthProtocolVersion::V2_0)
            .unwrap_err()
            .code(),
        24049
    );
    assert!(verify_pkce(None, None, None, OAuthProtocolVersion::V2_0).is_ok());
}

#[test]
fn oauth20_pkce_accepts_plain_and_implicit_plain_method() {
    for method in [Some("plain".parse().unwrap()), None] {
        assert!(
            verify_pkce(
                Some("verifier"),
                method,
                Some("verifier"),
                OAuthProtocolVersion::V2_0,
            )
            .is_ok()
        );
        assert_eq!(
            verify_pkce(
                Some("verifier"),
                method,
                Some("wrong"),
                OAuthProtocolVersion::V2_0,
            )
            .unwrap_err()
            .code(),
            24049
        );
    }
}
