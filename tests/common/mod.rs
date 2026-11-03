use identity_infrastructure::database;
use sea_orm::{ConnectionTrait, Database, DatabaseConnection, DbBackend, Statement};
use std::{env, future::Future, panic};
use url::Url;
use uuid::Uuid;

async fn sql(db: &DatabaseConnection, sql: &str) {
    db.execute_unprepared(sql).await.unwrap();
}

async fn row(db: &DatabaseConnection, sql: &str) -> sea_orm::QueryResult {
    db.query_one_raw(Statement::from_string(DbBackend::Postgres, sql.to_owned()))
        .await
        .unwrap()
        .unwrap()
}

pub async fn isolated<F, Fut>(case: F)
where
    F: FnOnce(DatabaseConnection) -> Fut + Send + 'static,
    Fut: Future<Output = ()> + Send + 'static,
{
    let raw = env::var("IDENTITY_TEST_DATABASE_URL").expect("explicit test database URL required");
    let mut url = Url::parse(&raw).unwrap();
    let expected =
        env::var("IDENTITY_TEST_DATABASE_NAME").expect("explicit test database name required");
    assert_eq!(url.path().trim_start_matches('/'), expected);
    assert_ne!(expected, "identity", "production database is forbidden");
    assert!(
        url.query_pairs().all(|(key, _)| key != "options"),
        "supply an unscoped test URL"
    );
    let admin = Database::connect(raw).await.unwrap();
    let schema = format!("repository_behavior_{}", Uuid::new_v4().simple());
    // SeaQuery has no schema namespace builder; these identifiers contain only a fixed prefix and UUID hex.
    sql(&admin, &format!("CREATE SCHEMA {schema}")).await;
    url.query_pairs_mut()
        .append_pair("options", &format!("-c search_path={schema}"));
    let db = Database::connect(url.as_str()).await.unwrap();
    let task_db = db.clone();
    let expected_schema = schema.clone();
    let outcome = tokio::spawn(async move {
        let actual: String = row(&task_db, "SELECT current_schema() AS name")
            .await
            .try_get("", "name")
            .unwrap();
        assert_eq!(
            actual, expected_schema,
            "migration and fixtures must stay inside the test schema"
        );
        database::migrate(&task_db).await.unwrap();
        case(task_db).await;
    })
    .await;
    db.close().await.unwrap();
    sql(&admin, &format!("DROP SCHEMA {schema} CASCADE")).await;
    admin.close().await.unwrap();
    if let Err(error) = outcome {
        panic::resume_unwind(error.into_panic());
    }
}
