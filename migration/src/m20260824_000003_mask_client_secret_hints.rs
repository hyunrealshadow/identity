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
                r#"
                UPDATE client_open_id_connect_credential
                SET hint = CASE
                    WHEN char_length(COALESCE(data ->> 'secret', '')) > 4
                        THEN '••••' || right(data ->> 'secret', 4)
                    ELSE '••••'
                END,
                updated_at = CURRENT_TIMESTAMP
                WHERE type = 'client_secret'
                "#,
            )
            .await?;

        Ok(())
    }

    async fn down(&self, _manager: &SchemaManager) -> Result<(), DbErr> {
        // Masking is intentionally irreversible: restoring an old hint could
        // expose a complete client secret again.
        Ok(())
    }
}
