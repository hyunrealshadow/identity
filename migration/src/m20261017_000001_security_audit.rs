use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .get_connection()
            .execute_unprepared(include_str!("security_audit.sql"))
            .await?;
        Ok(())
    }
    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // Preserve the journal on rollback. It contains historical security facts.
        manager
            .get_connection()
            .execute_unprepared(
                r#"
            DROP TRIGGER IF EXISTS identity_audit ON "user";
            DROP TRIGGER IF EXISTS identity_audit ON user_credential;
            DROP TRIGGER IF EXISTS identity_audit ON session;
            DROP TRIGGER IF EXISTS identity_audit ON login;
            DROP TRIGGER IF EXISTS identity_audit ON client_authorization;
            DROP FUNCTION IF EXISTS identity_security_audit();
        "#,
            )
            .await?;
        Ok(())
    }
}
