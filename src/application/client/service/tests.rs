use identity_domain::openid_connect::{
    GrantType, OpenIdConnectClientPlatformType, TokenEndpointAuthMethod,
};

use super::{new_secret, parse_jwks_uri, validate_settings};
use crate::{
    client::model::{ClientPlatform, ClientProtocolSettings, derived_auth_methods},
    error::{code::AppErrorCode, codes::client::ClientErrorCode},
};

fn settings(
    platforms: Vec<(OpenIdConnectClientPlatformType, &[&str])>,
    grant_types: &[GrantType],
    method: TokenEndpointAuthMethod,
) -> ClientProtocolSettings {
    ClientProtocolSettings {
        platforms: platforms
            .into_iter()
            .map(|(platform, uris)| ClientPlatform {
                platform,
                redirect_uris: uris.iter().map(|uri| (*uri).to_owned()).collect(),
            })
            .collect(),
        post_logout_redirect_uris: Vec::new(),
        grant_types: grant_types.to_vec(),
        // Submitted methods are ignored; only the public flow switch counts.
        token_endpoint_auth_methods: vec![method],
        allow_public_client_flow: method == TokenEndpointAuthMethod::None,
        require_pushed_authorization_requests: false,
        skip_consent: false,
        cors_enabled: false,
        oauth_version: None,
        include_scoped_claims_in_id_token: false,
        include_scoped_claims_in_access_token: false,
    }
}

fn rejected(settings: ClientProtocolSettings) -> u32 {
    validate_settings(settings).unwrap_err().code()
}

#[test]
fn web_settings_are_normalized_without_changing_redirect_spelling() {
    let validated = validate_settings(settings(
        vec![(
            OpenIdConnectClientPlatformType::Web,
            &[
                " https://app.example.com/Callback ",
                "https://app.example.com/Callback",
                "http://localhost:3000/cb",
            ],
        )],
        &[GrantType::RefreshToken, GrantType::AuthorizationCode],
        TokenEndpointAuthMethod::ClientSecretBasic,
    ))
    .unwrap();
    assert_eq!(
        validated.platforms[0].redirect_uris,
        [
            "https://app.example.com/Callback",
            "http://localhost:3000/cb"
        ]
    );
    assert_eq!(
        validated.grant_types,
        [GrantType::AuthorizationCode, GrantType::RefreshToken]
    );
}

#[test]
fn redirect_schemes_follow_the_platform() {
    let custom = ["com.example.app:/callback"];
    assert!(
        validate_settings(settings(
            vec![(OpenIdConnectClientPlatformType::Native, &custom)],
            &[GrantType::AuthorizationCode],
            TokenEndpointAuthMethod::None,
        ))
        .is_ok()
    );
    for (platform, uri) in [
        (
            OpenIdConnectClientPlatformType::Web,
            "com.example.app:/callback",
        ),
        (
            OpenIdConnectClientPlatformType::Web,
            "http://app.example.com/cb",
        ),
        (
            OpenIdConnectClientPlatformType::Web,
            "https://app.example.com/cb#part",
        ),
        (OpenIdConnectClientPlatformType::Web, "/relative"),
    ] {
        assert_eq!(
            rejected(settings(
                vec![(platform, &[uri])],
                &[GrantType::AuthorizationCode],
                TokenEndpointAuthMethod::ClientSecretBasic,
            )),
            ClientErrorCode::InvalidRedirectUri.code(),
            "{uri}"
        );
    }
}

#[test]
fn grant_and_authentication_combinations_are_enforced() {
    let web = || {
        vec![(
            OpenIdConnectClientPlatformType::Web,
            &["https://app.example.com/cb"][..],
        )]
    };
    for (platforms, grants, method, code) in [
        (
            web(),
            vec![GrantType::Implicit],
            TokenEndpointAuthMethod::ClientSecretBasic,
            ClientErrorCode::UnsupportedGrantType,
        ),
        (
            web(),
            vec![],
            TokenEndpointAuthMethod::ClientSecretBasic,
            ClientErrorCode::InvalidGrantTypes,
        ),
        (
            web(),
            vec![GrantType::RefreshToken, GrantType::ClientCredentials],
            TokenEndpointAuthMethod::ClientSecretBasic,
            ClientErrorCode::RefreshTokenRequiresInteractiveGrant,
        ),
        (
            Vec::new(),
            vec![GrantType::AuthorizationCode],
            TokenEndpointAuthMethod::ClientSecretBasic,
            ClientErrorCode::RedirectUriRequired,
        ),
        (
            vec![
                (
                    OpenIdConnectClientPlatformType::Web,
                    &["https://a.example.com/cb"][..],
                ),
                (
                    OpenIdConnectClientPlatformType::Web,
                    &["https://b.example.com/cb"][..],
                ),
            ],
            vec![GrantType::AuthorizationCode],
            TokenEndpointAuthMethod::ClientSecretBasic,
            ClientErrorCode::DuplicatePlatform,
        ),
    ] {
        assert_eq!(
            rejected(settings(platforms, &grants, method)),
            code.code(),
            "{code:?}"
        );
    }
    // A machine client needs no redirect URI.
    assert!(
        validate_settings(settings(
            Vec::new(),
            &[GrantType::ClientCredentials],
            TokenEndpointAuthMethod::ClientSecretPost,
        ))
        .is_ok()
    );
}

#[test]
fn auth_methods_follow_credentials_and_the_public_flow() {
    use TokenEndpointAuthMethod::{
        ClientSecretBasic, ClientSecretPost, None as NoAuth, PrivateKeyJwt,
    };
    assert!(derived_auth_methods(false, false, false).is_empty());
    assert_eq!(
        derived_auth_methods(true, false, false),
        [ClientSecretBasic, ClientSecretPost]
    );
    assert_eq!(derived_auth_methods(false, true, false), [PrivateKeyJwt]);
    assert_eq!(
        derived_auth_methods(true, true, true),
        [ClientSecretBasic, ClientSecretPost, PrivateKeyJwt, NoAuth]
    );
}

#[test]
fn submitted_auth_methods_are_ignored() {
    // Client credentials no longer depends on a declared method: the client
    // simply cannot authenticate until it has a credential.
    let validated = validate_settings(settings(
        Vec::new(),
        &[GrantType::ClientCredentials],
        TokenEndpointAuthMethod::PrivateKeyJwt,
    ))
    .unwrap();
    assert!(validated.token_endpoint_auth_methods.is_empty());
    assert!(!validated.allow_public_client_flow);
}

#[test]
fn jwks_uris_must_be_public_https() {
    assert!(parse_jwks_uri(" https://client.example.com/.well-known/jwks.json ").is_ok());
    for uri in [
        "",
        "http://client.example.com/jwks",
        "https://localhost/jwks",
        "https://10.0.0.1/jwks",
        "https://user:pass@client.example.com/jwks",
        "https://client.example.com/jwks#keys",
        "not a url",
    ] {
        assert_eq!(
            parse_jwks_uri(uri).unwrap_err().code(),
            ClientErrorCode::InvalidJwksUri.code(),
            "{uri}"
        );
    }
}

#[test]
fn issued_secrets_are_random_and_never_debug_printed() {
    let first = new_secret(30);
    let second = new_secret(30);
    assert_ne!(first.plaintext, second.plaintext);
    assert!(first.plaintext.len() >= 43);
    assert!(!format!("{first:?}").contains(&first.plaintext));
}
