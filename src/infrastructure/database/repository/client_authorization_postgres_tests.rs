use super::*;

#[tokio::test]
#[ignore = "requires isolated PostgreSQL via IDENTITY_TEST_DATABASE_URL"]
async fn refresh_family_revocation_and_expiration_execute_valid_postgres_sql() {
    let url = std::env::var("IDENTITY_TEST_DATABASE_URL").unwrap();
    let mut options = sea_orm::ConnectOptions::new(url);
    options.max_connections(1);
    let db = sea_orm::Database::connect(options).await.unwrap();
    // Temporary tables keep this regression independent of migrations and
    // prevent the fixture from changing persistent application data.
    db.execute_unprepared(
        r#"CREATE TEMP TABLE client (id bigint PRIMARY KEY, oid uuid);
        CREATE TEMP TABLE client_authorization (
            id bigint PRIMARY KEY, oid uuid, client_id bigint, "type" text,
            data jsonb, expires_at timestamptz, revoked_at timestamptz,
            updated_at timestamptz, is_expired boolean DEFAULT false
        )"#,
    )
    .await
    .unwrap();
    let client_oid = Uuid::new_v4();
    let root_oid = Uuid::new_v4();
    let child_oid = Uuid::new_v4();
    let access_oid = Uuid::new_v4();
    db.execute_raw(Statement::from_sql_and_values(
        DatabaseBackend::Postgres,
        "INSERT INTO client VALUES (1, $1)",
        [client_oid.into()],
    ))
    .await
    .unwrap();
    for (id, oid, type_, data) in [
        (1_i64, root_oid, "refresh_token", serde_json::json!({})),
        (
            2,
            child_oid,
            "refresh_token",
            serde_json::json!({"rotated_from": root_oid}),
        ),
        (
            3,
            access_oid,
            "access_token",
            serde_json::json!({"refresh_token_oid": child_oid}),
        ),
    ] {
        db.execute_raw(Statement::from_sql_and_values(
            DatabaseBackend::Postgres,
            r#"INSERT INTO client_authorization (id, oid, client_id, "type", data, expires_at)
            VALUES ($1, $2, 1, $3, $4, CURRENT_TIMESTAMP - INTERVAL '1 hour')"#,
            [id.into(), oid.into(), type_.into(), data.into()],
        ))
        .await
        .unwrap();
    }
    let repo = ClientAuthorizationRepositoryImpl::new(db.clone());
    repo.revoke_refresh_token_family(child_oid, client_oid, Utc::now())
        .await
        .unwrap();
    let count = db
        .query_one_raw(Statement::from_string(
            DatabaseBackend::Postgres,
            "SELECT COUNT(*) AS count FROM client_authorization WHERE revoked_at IS NOT NULL",
        ))
        .await
        .unwrap()
        .unwrap()
        .try_get::<i64>("", "count")
        .unwrap();
    assert_eq!(
        count, 3,
        "replay must revoke the ancestor, descendant and access token"
    );
    assert_eq!(expire_due_authorizations_batch(&db).await.unwrap(), 3);
    assert_eq!(expire_due_authorizations_batch(&db).await.unwrap(), 0);
}
