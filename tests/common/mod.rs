#![allow(dead_code)]

use identity_application::data_protection::DataProtector;
use identity_domain::data_protection::DataProtectionError;
use identity_infrastructure::{database, email::EmailQueue, jobs};
use sea_orm::{ConnectionTrait, Database, DatabaseConnection, DbBackend, Statement};
use std::{env, future::Future, panic, pin::Pin, sync::Arc};
use tokio::sync::OnceCell;
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
    // Messages the case queued live in the shared queue table under the
    // case's own queue name.
    let queue_exists: Option<String> = admin
        .query_one_raw(Statement::from_string(
            DbBackend::Postgres,
            "SELECT to_regclass('apalis.jobs')::text AS name".to_owned(),
        ))
        .await
        .unwrap()
        .and_then(|row| row.try_get("", "name").ok());
    if queue_exists.is_some() {
        sql(
            &admin,
            &format!(
                "DELETE FROM apalis.jobs WHERE job_type = '{}'",
                test_queue(&schema)
            ),
        )
        .await;
    }
    sql(&admin, &format!("DROP SCHEMA {schema} CASCADE")).await;
    admin.close().await.unwrap();
    if let Err(error) = outcome {
        panic::resume_unwind(error.into_panic());
    }
}

fn test_queue(schema: &str) -> String {
    format!("test.{schema}")
}

static QUEUE_READY: OnceCell<()> = OnceCell::const_new();

/// An email queue apart from a running instance's: messages a case queues
/// go to a queue named after its schema, which no worker reads and which is
/// cleared when the case ends.
pub async fn email_queue(db: &DatabaseConnection) -> EmailQueue {
    QUEUE_READY
        .get_or_init(|| async {
            // Prepared once on an unscoped connection, so the queue's schema
            // and extensions never land in a test schema.
            let raw = env::var("IDENTITY_TEST_DATABASE_URL")
                .expect("explicit test database URL required");
            let admin = Database::connect(raw).await.unwrap();
            jobs::prepare_queue(admin.get_postgres_connection_pool())
                .await
                .unwrap();
            admin.close().await.unwrap();
        })
        .await;
    EmailQueue::new(Arc::new(PlainProtector)).with_queue(test_queue(&current_schema(db).await))
}

/// How many messages the case has queued.
pub async fn queued_emails(db: &DatabaseConnection) -> i64 {
    let queue = test_queue(&current_schema(db).await);
    db.query_one_raw(Statement::from_sql_and_values(
        DbBackend::Postgres,
        "SELECT count(*)::bigint AS n FROM apalis.jobs WHERE job_type = $1",
        [queue.into()],
    ))
    .await
    .unwrap()
    .unwrap()
    .try_get("", "n")
    .unwrap()
}

async fn current_schema(db: &DatabaseConnection) -> String {
    row(db, "SELECT current_schema() AS name")
        .await
        .try_get("", "name")
        .unwrap()
}

/// Keeps queued messages readable; the tests check only that they exist.
struct PlainProtector;

impl DataProtector for PlainProtector {
    fn protect<'life0, 'life1, 'life2, 'async_trait>(
        &'life0 self,
        purpose: &'life1 str,
        plaintext: &'life2 [u8],
    ) -> Pin<Box<dyn Future<Output = Result<String, DataProtectionError>> + Send + 'async_trait>>
    where
        'life0: 'async_trait,
        'life1: 'async_trait,
        'life2: 'async_trait,
        Self: 'async_trait,
    {
        let result = String::from_utf8(plaintext.to_vec())
            .map(|text| format!("{purpose}|{text}"))
            .map_err(|_| DataProtectionError::InvalidProtectedPayload);
        Box::pin(async move { result })
    }

    fn unprotect<'life0, 'life1, 'life2, 'async_trait>(
        &'life0 self,
        purpose: &'life1 str,
        token: &'life2 str,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<u8>, DataProtectionError>> + Send + 'async_trait>>
    where
        'life0: 'async_trait,
        'life1: 'async_trait,
        'life2: 'async_trait,
        Self: 'async_trait,
    {
        let prefix = format!("{purpose}|");
        let result = token
            .strip_prefix(&prefix)
            .ok_or(DataProtectionError::InvalidProtectedPayload)
            .map(|rest| rest.as_bytes().to_vec());
        Box::pin(async move { result })
    }
}
