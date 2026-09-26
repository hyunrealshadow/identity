use sea_orm_migration::async_trait;
use sea_orm_migration::prelude::{
    ConnectionTrait, DbErr, DeriveMigrationName, MigrationTrait, SchemaManager,
};

#[derive(DeriveMigrationName)]
pub struct Migration;

const REFRESH_TOKEN_ROTATED_FROM_INDEX: &str =
    "idx_client_authorization_refresh_token_rotated_from";
const ACCESS_TOKEN_REFRESH_TOKEN_OID_INDEX: &str =
    "idx_client_authorization_access_token_refresh_token_oid";

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .get_connection()
            .execute_unprepared(&format!(
                r#"CREATE INDEX IF NOT EXISTS "{REFRESH_TOKEN_ROTATED_FROM_INDEX}"
               ON "client_authorization" (("data"->>'rotated_from'))
               WHERE "type" = 'refresh_token'"#
            ))
            .await?;
        manager
            .get_connection()
            .execute_unprepared(&format!(
                r#"CREATE INDEX IF NOT EXISTS "{ACCESS_TOKEN_REFRESH_TOKEN_OID_INDEX}"
               ON "client_authorization" (("data"->>'refresh_token_oid'))
               WHERE "type" = 'access_token'"#
            ))
            .await?;
        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        for index in [
            ACCESS_TOKEN_REFRESH_TOKEN_OID_INDEX,
            REFRESH_TOKEN_ROTATED_FROM_INDEX,
        ] {
            manager
                .get_connection()
                .execute_unprepared(&format!(r#"DROP INDEX IF EXISTS "{index}""#))
                .await?;
        }
        Ok(())
    }
}
