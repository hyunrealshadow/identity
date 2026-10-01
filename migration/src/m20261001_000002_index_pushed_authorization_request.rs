use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .get_connection()
            .execute_unprepared(
                r#"CREATE UNIQUE INDEX "idx_client_authorization_par_digest"
               ON "client_authorization" (("data"->>'request_uri_digest'))
               WHERE "type" = 'pushed_authorization_request'"#,
            )
            .await?;
        Ok(())
    }
    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .get_connection()
            .execute_unprepared(r#"DROP INDEX "idx_client_authorization_par_digest""#)
            .await?;
        Ok(())
    }
}
