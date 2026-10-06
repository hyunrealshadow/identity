use chrono::Duration;
use identity_domain::{
    auth::SessionOid,
    openid_connect::{
        API_RESOURCE, ScopeSet,
        resource::{OAuthResource, OAuthResourceRepository, OAuthResourceRepositoryError},
    },
};

use crate::openid_connect::token::tests::{fixtures::*, *};

const PROFILE: &str = "https://api.example.com/profile";
const EMAIL: &str = "https://api.example.com/email";

struct Resources;
#[async_trait::async_trait]
impl OAuthResourceRepository for Resources {
    async fn find_by_uri(
        &self,
        uri: &str,
    ) -> Result<Option<OAuthResource>, OAuthResourceRepositoryError> {
        Ok(match uri {
            PROFILE => Some(OAuthResource {
                uri: uri.to_owned(),
                scopes: vec!["profile".to_owned()],
                enabled: true,
            }),
            EMAIL => Some(OAuthResource {
                uri: uri.to_owned(),
                scopes: vec!["email".to_owned()],
                enabled: true,
            }),
            "urn:disabled" => Some(OAuthResource {
                uri: uri.to_owned(),
                scopes: vec!["profile".to_owned()],
                enabled: false,
            }),
            "urn:account" => Some(OAuthResource {
                uri: uri.to_owned(),
                scopes: vec!["account.read".to_owned()],
                enabled: true,
            }),
            "urn:shared" => Some(OAuthResource {
                uri: uri.to_owned(),
                scopes: vec!["profile".to_owned(), "email".to_owned()],
                enabled: true,
            }),
            API_RESOURCE => Some(OAuthResource {
                uri: uri.to_owned(),
                scopes: vec!["account".to_owned()],
                enabled: false,
            }),
            _ => None,
        })
    }
}

#[tokio::test]
async fn resource_validation_rejects_invalid_targets_and_deduplicates_exact_uris() {
    let mut provider = provider_service();
    Arc::get_mut(&mut provider).unwrap().resource_repo = Some(Arc::new(Resources));
    for uri in [
        "relative",
        "https://api.example.com/profile#fragment",
        "urn:disabled",
        "urn:unknown",
        "https://API.example.com/profile",
        "https://api.example.com/%ZZ",
    ] {
        let error = provider
            .select_resources(&[uri.to_owned()], &[], "profile")
            .await
            .err()
            .unwrap();
        assert_eq!(error.code(), 10006, "{uri}");
    }
    let selected = provider
        .select_resources(
            &[PROFILE.to_owned(), PROFILE.to_owned()],
            &[],
            "openid profile email offline_access",
        )
        .await
        .unwrap();
    assert_eq!(selected.resources, [PROFILE]);
    assert_eq!(selected.scope, "openid profile offline_access");
    assert_eq!(
        provider
            .select_resources(&["urn:account".to_owned()], &[], "account")
            .await
            .unwrap()
            .scope,
        "account.read"
    );
    assert_eq!(
        provider
            .select_resources(&[], &[], "account.read")
            .await
            .err()
            .unwrap()
            .code(),
        10006
    );
    assert_eq!(
        provider
            .select_resources(&[EMAIL.to_owned()], &[], "openid profile offline_access")
            .await
            .err()
            .unwrap()
            .code(),
        10006
    );
    let scope = ScopeSet::parse("profile email").unwrap();
    assert!(
        provider
            .validate_authorization_resources(&[PROFILE.to_owned(), EMAIL.to_owned()], &scope)
            .await
            .is_ok()
    );
    assert_eq!(
        provider
            .select_resources(
                &[PROFILE.to_owned(), EMAIL.to_owned()],
                &[],
                "openid profile email offline_access"
            )
            .await
            .err()
            .unwrap()
            .code(),
        10006
    );
    let shared = provider
        .select_resources(
            &[PROFILE.to_owned(), "urn:shared".to_owned()],
            &[],
            "openid profile email offline_access",
        )
        .await
        .unwrap();
    assert_eq!(shared.resources, [PROFILE, "urn:shared"]);
    assert_eq!(shared.scope, "openid profile offline_access");
    assert_eq!(
        provider
            .validate_authorization_resources(&[PROFILE.to_owned()], &scope)
            .await
            .unwrap_err()
            .code(),
        10006
    );
}

#[tokio::test]
async fn resource_selection_preserves_the_full_refresh_grant_and_rejects_expansion_before_consumption()
 {
    let repo = Arc::new(mock_client_auth_repo());
    let user_oid = Uuid::new_v4();
    let key = key_for_algorithm("RS256");
    let public = match &key.data {
        KeyData::Asymmetric(data) => data.public_key.clone(),
        _ => unreachable!(),
    };
    let mut service = build_token_service_with_key(repo.clone(), key, user_oid);
    let mut provider = provider_service();
    Arc::get_mut(&mut provider).unwrap().resource_repo = Some(Arc::new(Resources));
    service.provider_service = provider;
    let record = repo
        .create(
            Uuid::nil(),
            ClientAuthorizationData::AuthorizationCode(AuthorizationCodeData {
                resources: vec![
                    PROFILE.to_owned(),
                    EMAIL.to_owned(),
                    "urn:shared".to_owned(),
                ],
                scope: "openid profile email offline_access".to_owned(),
                nonce: None,
                code_challenge: None,
                code_challenge_method: None,
                user_oid: user_oid.to_string(),
                session_oid: SessionOid::from(Uuid::new_v4()),
                protected_session_id: None,
                auth_time: None,
                acr: None,
                amr: vec![],
                claims: None,
                redirect_uri: "https://client.example.com/callback".to_owned(),
                redirect_uri_was_supplied: true,
            }),
            Utc::now() + Duration::minutes(10),
        )
        .await
        .unwrap();
    let mut params = AuthorizationCodeGrantParams {
        resources: vec!["urn:account".to_owned()],
        code: STANDARD.encode(record.oid.as_bytes()),
        redirect_uri: Some("https://client.example.com/callback".to_owned()),
        client_id: Some(Uuid::nil().to_string()),
        client_secret: Some("secret-123".to_owned()),
        client_secret_basic: true,
        client_assertion_type: None,
        client_assertion: None,
        code_verifier: None,
    };
    assert_eq!(
        service
            .exchange_authorization_code(params.clone())
            .await
            .unwrap_err()
            .code(),
        10006
    );
    assert!(
        repo.find_by_oid(record.oid)
            .await
            .unwrap()
            .unwrap()
            .revoked_at
            .is_none()
    );
    params.resources = vec![PROFILE.to_owned(), "urn:shared".to_owned()];
    let initial = service.exchange_authorization_code(params).await.unwrap();
    assert_eq!(initial.scope, "openid profile offline_access");
    let verifier = RS256.verifier_from_pem(public.as_bytes()).unwrap();
    let (access, _) = jwt::decode_with_verifier(&initial.access_token, &verifier).unwrap();
    assert_eq!(access.audience().unwrap(), [PROFILE, "urn:shared"]);
    let (id, _) = jwt::decode_with_verifier(initial.id_token.as_ref().unwrap(), &verifier).unwrap();
    assert_eq!(id.audience().unwrap(), [Uuid::nil().to_string().as_str()]);
    let refresh_token = initial.refresh_token.unwrap();
    let refresh_oid = Uuid::from_slice(&STANDARD.decode(&refresh_token).unwrap()).unwrap();
    let stored = repo.find_by_oid(refresh_oid).await.unwrap().unwrap();
    let ClientAuthorizationData::RefreshToken(data) = stored.data else {
        panic!("refresh data")
    };
    assert_eq!(data.resources, [PROFILE, EMAIL, "urn:shared"]);
    assert_eq!(data.scope, "openid profile email offline_access");
    let mut refresh = RefreshTokenGrantParams {
        resources: vec!["urn:account".to_owned()],
        refresh_token,
        scope: None,
        client_id: Some(Uuid::nil().to_string()),
        client_secret: Some("secret-123".to_owned()),
        client_secret_basic: true,
        client_assertion_type: None,
        client_assertion: None,
    };
    assert_eq!(
        service
            .exchange_refresh_token(refresh.clone())
            .await
            .unwrap_err()
            .code(),
        10006
    );
    assert!(
        repo.find_by_oid(refresh_oid)
            .await
            .unwrap()
            .unwrap()
            .revoked_at
            .is_none()
    );
    refresh.resources = vec![EMAIL.to_owned()];
    let refreshed = service.exchange_refresh_token(refresh).await.unwrap();
    assert_eq!(refreshed.scope, "openid email offline_access");
    let (access, _) = jwt::decode_with_verifier(&refreshed.access_token, &verifier).unwrap();
    assert_eq!(access.audience().unwrap(), [EMAIL]);
    let next_oid =
        Uuid::from_slice(&STANDARD.decode(refreshed.refresh_token.unwrap()).unwrap()).unwrap();
    let next = repo.find_by_oid(next_oid).await.unwrap().unwrap();
    let ClientAuthorizationData::RefreshToken(next) = next.data else {
        panic!("refresh data")
    };
    assert_eq!(next.resources, [PROFILE, EMAIL, "urn:shared"]);
    assert_eq!(next.scope, "openid profile email offline_access");
    let multiple = service
        .exchange_refresh_token(RefreshTokenGrantParams {
            resources: vec![],
            refresh_token: STANDARD.encode(next_oid.as_bytes()),
            scope: None,
            client_id: Some(Uuid::nil().to_string()),
            client_secret: Some("secret-123".to_owned()),
            client_secret_basic: true,
            client_assertion_type: None,
            client_assertion: None,
        })
        .await
        .unwrap_err();
    assert_eq!(multiple.code(), 10006);
    assert!(
        repo.find_by_oid(next_oid)
            .await
            .unwrap()
            .unwrap()
            .revoked_at
            .is_none()
    );
}
