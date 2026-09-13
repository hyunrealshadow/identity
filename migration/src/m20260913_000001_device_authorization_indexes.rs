use sea_orm_migration::async_trait;
use sea_orm_migration::prelude::{
    ConnectionTrait, DbErr, DeriveMigrationName, MigrationTrait, SchemaManager,
};

#[derive(DeriveMigrationName)]
pub struct Migration;

const DEVICE_CODE_DIGEST_INDEX: &str = "idx_client_authorization_device_code_digest";
const ACTIVE_USER_CODE_INDEX: &str = "idx_client_authorization_active_user_code";
const DEVICE_AUTHORIZATION_USER_INDEX: &str = "idx_client_authorization_device_authorization_user";

/// Indexes backing RFC 8628 device requests and the relations they create.
///
/// Requests and relations live in `client_authorization`, so their lookup keys
/// sit inside the `data` document. The two unique indexes are what makes a
/// device code digest collision-free and a user code unique among the requests
/// that are still answerable: consumed and revoked requests leave the partial
/// index, which frees their user code for reuse.
#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .get_connection()
            .execute_unprepared(&format!(
                r#"CREATE UNIQUE INDEX IF NOT EXISTS "{DEVICE_CODE_DIGEST_INDEX}"
                   ON "client_authorization" (("data"->>'device_code_digest'))
                   WHERE "type" = 'device_authorization_request'"#
            ))
            .await?;
        manager
            .get_connection()
            .execute_unprepared(&format!(
                r#"CREATE UNIQUE INDEX IF NOT EXISTS "{ACTIVE_USER_CODE_INDEX}"
                   ON "client_authorization" (("data"->>'user_code'))
                   WHERE "type" = 'device_authorization_request'
                     AND "completed_at" IS NULL
                     AND "revoked_at" IS NULL"#
            ))
            .await?;
        manager
            .get_connection()
            .execute_unprepared(&format!(
                r#"CREATE INDEX IF NOT EXISTS "{DEVICE_AUTHORIZATION_USER_INDEX}"
                   ON "client_authorization" (("data"->>'user_oid'))
                   WHERE "type" = 'device_authorization'"#
            ))
            .await?;
        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        for index in [
            DEVICE_AUTHORIZATION_USER_INDEX,
            ACTIVE_USER_CODE_INDEX,
            DEVICE_CODE_DIGEST_INDEX,
        ] {
            manager
                .get_connection()
                .execute_unprepared(&format!(r#"DROP INDEX IF EXISTS "{index}""#))
                .await?;
        }
        Ok(())
    }
}
