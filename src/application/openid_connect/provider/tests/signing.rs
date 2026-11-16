use super::*;

#[tokio::test]
async fn discovery_advertises_only_published_signing_algorithms() {
    let key = make_asymmetric_key(generate_rsa_pem());
    let binding = KeyJwk {
        oid: KeyJwkOid(Uuid::new_v4()),
        key_oid: key.oid,
        algorithm: JwkAlgorithm::Signing(JwaSigningAlgorithm::Rs256),
        jwk: PublicJwk::Rsa {
            key_use: Some("sig".to_owned()),
            alg: Some("RS256".to_owned()),
            kid: Some(Uuid::new_v4().to_string()),
            n: "AQAB".to_owned(),
            e: "AQAB".to_owned(),
            x5c: None,
            x5t: None,
            x5t_s256: None,
        },
        created_at: Utc::now(),
    };
    let mut jwk_repo = MockKeyJwkRepository::new();
    jwk_repo
        .expect_list_active()
        .returning(move || Ok(vec![binding.clone()]));
    let service = OpenIdProviderService::for_test(
        SettingsSnapshot::default()
            .with_section(&AppSettings {
                console_domain: None,
                domain: Some("https://identity.example.com".to_owned()),
                login_domain: None,
                login_client_id: None,
                console_client_id: None,
            })
            .with_section(&InstallationSettings {
                initialized: true,
                initialized_at: None,
            }),
    )
    .await
    .with_key_repo(Arc::new(key_repo_with_keys(vec![key])))
    .with_key_jwk_repo(Arc::new(jwk_repo));

    let metadata = service.discovery_metadata().await.unwrap();
    assert_eq!(
        metadata.id_token_signing_alg_values_supported,
        expected_id_token_algorithms(&["RS256"]),
    );
}

#[tokio::test]
async fn discovery_uses_all_detected_key_repo_algorithms() {
    let service = OpenIdProviderService::for_test(
        SettingsSnapshot::default()
            .with_section(&AppSettings {
                console_domain: None,
                domain: Some("https://identity.example.com".to_owned()),
                login_domain: None,
                login_client_id: None,
                console_client_id: None,
            })
            .with_section(&InstallationSettings {
                initialized: true,
                initialized_at: None,
            }),
    )
    .await
    .with_key_repo(Arc::new(key_repo_with_keys(vec![
        make_asymmetric_key(generate_rsa_pem()),
        make_asymmetric_key(generate_rsa_pss_pem("PS256")),
        make_asymmetric_key(generate_rsa_pss_pem("PS384")),
        make_asymmetric_key(generate_rsa_pss_pem("PS512")),
        make_asymmetric_key(generate_ec_p256_pem()),
        make_asymmetric_key(generate_ec_p384_pem()),
        make_asymmetric_key(generate_ec_p521_pem()),
        make_asymmetric_key(generate_ec_secp256k1_pem()),
        make_asymmetric_key(generate_ed25519_pem()),
    ])))
    .with_signing_algorithm_detector(test_signing_algorithm_detector());

    let metadata = service.discovery_metadata().await.unwrap();

    assert_eq!(
        metadata.id_token_signing_alg_values_supported,
        expected_id_token_algorithms(&[
            "ES256", "ES256K", "ES384", "ES512", "EdDSA", "PS256", "PS384", "PS512", "RS256",
            "RS384", "RS512",
        ])
    );
}

#[tokio::test]
async fn discovery_falls_back_to_capabilities_when_key_repo_has_no_detected_algorithms() {
    let service = OpenIdProviderService::for_test(
        SettingsSnapshot::default()
            .with_section(&AppSettings {
                console_domain: None,
                domain: Some("https://identity.example.com".to_owned()),
                login_domain: None,
                login_client_id: None,
                console_client_id: None,
            })
            .with_section(&InstallationSettings {
                initialized: true,
                initialized_at: None,
            }),
    )
    .await
    .with_key_repo(Arc::new(key_repo_with_keys(vec![])));

    let metadata = service.discovery_metadata().await.unwrap();

    assert_eq!(
        metadata.id_token_signing_alg_values_supported,
        expected_id_token_algorithms(&["ES256"])
    );
}

#[tokio::test]
async fn discovery_maps_key_repo_errors() {
    let service = OpenIdProviderService::for_test(
        SettingsSnapshot::default()
            .with_section(&AppSettings {
                console_domain: None,
                domain: Some("https://identity.example.com".to_owned()),
                login_domain: None,
                login_client_id: None,
                console_client_id: None,
            })
            .with_section(&InstallationSettings {
                initialized: true,
                initialized_at: None,
            }),
    )
    .await
    .with_key_repo(Arc::new(key_repo_failing()));

    let error = service.discovery_metadata().await.unwrap_err();

    assert_eq!(error.code(), 20005);
}

fn rsa_binding(key_oid: identity_domain::key::KeyOid, algorithm: JwkAlgorithm) -> KeyJwk {
    KeyJwk {
        oid: KeyJwkOid(Uuid::new_v4()),
        key_oid,
        algorithm,
        jwk: PublicJwk::Rsa {
            key_use: None,
            alg: Some(algorithm.as_str().to_owned()),
            kid: Some(Uuid::new_v4().to_string()),
            n: "AQAB".to_owned(),
            e: "AQAB".to_owned(),
            x5c: None,
            x5t: None,
            x5t_s256: None,
        },
        created_at: Utc::now(),
    }
}

async fn provider_with_bindings(bindings: Vec<JwkAlgorithm>) -> OpenIdProviderService {
    let key = make_asymmetric_key(generate_rsa_pem());
    let bindings = bindings
        .into_iter()
        .map(|algorithm| rsa_binding(key.oid, algorithm))
        .collect::<Vec<_>>();
    let mut jwk_repo = MockKeyJwkRepository::new();
    jwk_repo
        .expect_list_active()
        .returning(move || Ok(bindings.clone()));
    OpenIdProviderService::for_test(
        SettingsSnapshot::default()
            .with_section(&AppSettings {
                console_domain: None,
                domain: Some("https://identity.example.com".to_owned()),
                login_domain: None,
                login_client_id: None,
                console_client_id: None,
            })
            .with_section(&InstallationSettings {
                initialized: true,
                initialized_at: None,
            }),
    )
    .await
    .with_key_repo(Arc::new(key_repo_with_keys(vec![key])))
    .with_key_jwk_repo(Arc::new(jwk_repo))
}

#[tokio::test]
async fn discovery_follows_active_keys_while_client_options_do_not() {
    use identity_domain::key::JwaEncryptionAlgorithm;

    let service = provider_with_bindings(vec![
        JwkAlgorithm::Signing(JwaSigningAlgorithm::Rs256),
        JwkAlgorithm::Encryption(JwaEncryptionAlgorithm::RsaOaep256),
    ])
    .await;
    let metadata = service.discovery_metadata().await.unwrap();
    assert_eq!(
        metadata.request_object_encryption_alg_values_supported,
        Some(vec!["RSA-OAEP-256".to_owned()])
    );
    assert!(
        metadata
            .request_object_encryption_enc_values_supported
            .is_some_and(|values| !values.is_empty())
    );
    // A client may list algorithms the provider supports but has no key for
    // now; each issuance picks the first listed algorithm with a key.
    let options = service.client_metadata_options();
    assert!(options.request_object_encryption_algs.len() > 1);
    for algorithm in ["ES256", "PS256", "RS256", "EdDSA"] {
        assert!(
            options
                .id_token_signing_algs
                .contains(&algorithm.to_owned()),
            "{algorithm}"
        );
    }
    assert_eq!(options.userinfo_signing_algs, options.id_token_signing_algs);

    // Without an encryption key discovery offers no request object
    // encryption, but the client options stay the same.
    let signing_only =
        provider_with_bindings(vec![JwkAlgorithm::Signing(JwaSigningAlgorithm::Rs256)]).await;
    let metadata = signing_only.discovery_metadata().await.unwrap();
    assert_eq!(
        metadata.request_object_encryption_alg_values_supported,
        None
    );
    assert_eq!(
        metadata.request_object_encryption_enc_values_supported,
        None
    );
    assert_eq!(signing_only.client_metadata_options(), options);
}
