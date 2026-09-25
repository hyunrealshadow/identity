use sea_orm_migration::async_trait;
use sea_orm_migration::prelude::{
    ConnectionTrait, DbErr, DeriveMigrationName, MigrationTrait, SchemaManager,
};

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .get_connection()
            .execute_unprepared(
                r#"CREATE INDEX IF NOT EXISTS "idx_refresh_token_rotated_from"
               ON "client_authorization" (("data"->>'rotated_from'))
               WHERE "type" = 'refresh_token'"#,
            )
            .await?;
        manager
            .get_connection()
            .execute_unprepared(
                r#"CREATE INDEX IF NOT EXISTS "idx_access_token_refresh_token_oid"
               ON "client_authorization" (("data"->>'refresh_token_oid'))
               WHERE "type" = 'access_token'"#,
            )
            .await?;
        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .get_connection()
            .execute_unprepared(r#"DROP INDEX IF EXISTS "idx_access_token_refresh_token_oid""#)
            .await?;
        manager
            .get_connection()
            .execute_unprepared(r#"DROP INDEX IF EXISTS "idx_refresh_token_rotated_from""#)
            .await?;
        Ok(())
    }
}
