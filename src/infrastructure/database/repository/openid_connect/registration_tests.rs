use identity_domain::client::model::ClientProtocol;
use sea_orm::{DatabaseBackend, MockDatabase, MockExecResult};
use serde_json::json;

use super::OpenIdConnectClientRepositoryImpl;
use crate::database::entity::{
    client, client_authorization, client_openid_connect, client_openid_connect_credential,
};
use chrono::{Duration, Utc};
use identity_domain::{
    client::model::Client,
    openid_connect::{
        OpenIdConnectClientMetadata, OpenIdConnectClientRegistration,
        OpenIdConnectClientRegistrationRepository, OpenIdConnectClientRepositoryError,
    },
};
use uuid::Uuid;

fn registration(oid: Uuid) -> OpenIdConnectClientRegistration {
    OpenIdConnectClientRegistration {
        client: Client {
            oid,
            protocol: ClientProtocol::OpenIdConnect,
            name: "Updated".into(),
            names: vec![],
            description: None,
            built_in: false,
            created_at: Utc::now(),
            updated_at: Some(Utc::now()),
        },
        metadata: OpenIdConnectClientMetadata::default(),
        platforms: vec![],
        assigned_scopes: vec![],
        credentials: vec![],
        registration_access_token: "rat".into(),
    }
}

fn client_row(oid: Uuid) -> client::Model {
    client::Model {
        id: 1,
        oid,
        protocol: "openid_connect".into(),
        name: "Old".into(),
        names: None,
        description: None,
        built_in: false,
        created_at: Utc::now().into(),
        updated_at: None,
    }
}

fn metadata_row() -> client_openid_connect::Model {
    client_openid_connect::Model {
        id: 1,
        client_id: 2,
        post_logout_redirect_uris: None,
        frontchannel_logout_uri: Some("https://rp.example.com/frontchannel_logout".to_owned()),
        frontchannel_logout_session_required: Some(true),
        backchannel_logout_uri: Some("https://rp.example.com/backchannel_logout".to_owned()),
        backchannel_logout_session_required: Some(true),
        response_types: None,
        grant_types: None,
        contacts: None,
        logo_uri: None,
        client_uri: None,
        policy_uri: None,
        tos_uri: None,
        sector_identifier_uri: None,
        subject_type: None,
        id_token_signed_response_algs: Some(json!(["RS256", "ES256"])),
        id_token_encrypted_response_algs: None,
        id_token_encrypted_response_encs: None,
        userinfo_signed_response_algs: None,
        userinfo_encrypted_response_algs: None,
        userinfo_encrypted_response_encs: None,
        request_object_signing_algs: None,
        request_object_encryption_algs: None,
        request_object_encryption_encs: None,
        token_endpoint_auth_methods: Some(json!(["client_secret_basic", "none"])),
        token_endpoint_auth_signing_algs: None,
        default_max_age: None,
        require_auth_time: None,
        default_acr_values: None,
        initiate_login_uri: None,
        request_uris: None,
        settings: json!({}),
        created_at: Utc::now().into(),
        updated_at: None,
    }
}

fn auth_row() -> client_authorization::Model {
    client_authorization::Model {
        id: 1,
        oid: Uuid::new_v4(),
        client_id: 1,
        r#type: "registration_access_token".into(),
        data: json!({"token":"rat"}),
        expires_at: (Utc::now() + Duration::days(1)).into(),
        completed_at: None,
        revoked_at: None,
        is_expired: false,
        created_at: Utc::now().into(),
        updated_at: None,
    }
}

#[tokio::test]
async fn update_rechecks_token_and_secret_before_mutation() {
    let oid = Uuid::new_v4();
    for (token, secret) in [("wrong", None), ("rat", Some("chosen-secret".to_owned()))] {
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_results([vec![client_row(oid)]])
            .append_query_results([vec![auth_row()]])
            .append_query_results([Vec::<client_openid_connect_credential::Model>::new()])
            .into_connection();
        let repo = OpenIdConnectClientRepositoryImpl::new(db.clone());
        let error = repo
            .update(registration(oid), token, secret)
            .await
            .unwrap_err();
        if token == "wrong" {
            assert!(matches!(
                error,
                OpenIdConnectClientRepositoryError::ClientNotFound
            ));
        } else {
            assert!(matches!(
                error,
                OpenIdConnectClientRepositoryError::InvalidMetadataValue {
                    field: "client_secret",
                    ..
                }
            ));
        }
        let log = format!("{:?}", db.into_transaction_log());
        assert!(log.contains("FOR UPDATE"), "{log}");
        assert!(log.contains("ROLLBACK"), "{log}");
        assert!(!log.contains("DELETE"), "{log}");
    }
}

#[tokio::test]
async fn update_replaces_metadata_in_one_transaction_without_deleting_grants() {
    let oid = Uuid::new_v4();
    let db = MockDatabase::new(DatabaseBackend::Postgres)
        .append_query_results([vec![client_row(oid)]])
        .append_query_results([vec![auth_row()]])
        .append_query_results([vec![client_row(oid)]])
        .append_query_results([vec![metadata_row()]])
        .append_exec_results((0..5).map(|_| MockExecResult {
            last_insert_id: 1,
            rows_affected: 1,
        }))
        .into_connection();
    let repo = OpenIdConnectClientRepositoryImpl::new(db.clone());
    repo.update(registration(oid), "rat", None).await.unwrap();
    let log = format!("{:?}", db.into_transaction_log());
    assert!(log.contains("COMMIT"), "{log}");
    assert!(log.contains(r#"UPDATE \"client\""#), "{log}");
    assert!(!log.contains(r#"DELETE FROM \"client\""#), "{log}");
    assert!(
        !log.contains(r#"DELETE FROM \"client_authorization\""#),
        "{log}"
    );
    assert!(
        !log.contains(r#"INSERT INTO \"client_authorization\""#),
        "{log}"
    );
}
