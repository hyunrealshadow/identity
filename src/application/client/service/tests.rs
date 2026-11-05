use identity_domain::openid_connect::{
    GrantType, OpenIdConnectClientPlatformType, TokenEndpointAuthMethod,
};

use super::{new_secret, validate_settings};
use crate::{
    client::model::{ClientPlatform, ClientProtocolSettings},
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
        token_endpoint_auth_method: method,
        require_pushed_authorization_requests: false,
        skip_consent: false,
        cors_enabled: false,
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
            web(),
            vec![GrantType::ClientCredentials],
            TokenEndpointAuthMethod::None,
            ClientErrorCode::PublicClientGrantNotAllowed,
        ),
        (
            web(),
            vec![GrantType::AuthorizationCode],
            TokenEndpointAuthMethod::PrivateKeyJwt,
            ClientErrorCode::UnsupportedAuthMethod,
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
fn issued_secrets_are_random_and_never_debug_printed() {
    let first = new_secret(30);
    let second = new_secret(30);
    assert_ne!(first.plaintext, second.plaintext);
    assert!(first.plaintext.len() >= 43);
    assert!(!format!("{first:?}").contains(&first.plaintext));
}
