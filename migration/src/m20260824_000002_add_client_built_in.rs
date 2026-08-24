use crate::m20260306_031058_create_client::Client;
use sea_orm_migration::prelude::{
    ConnectionTrait, DbErr, DeriveIden, DeriveMigrationName, MigrationTrait, SchemaManager, Table,
};
use sea_orm_migration::schema::boolean;
use sea_orm_migration::{async_trait, sea_orm};

#[derive(DeriveMigrationName)]
pub struct Migration;

#[derive(DeriveIden)]
enum ClientBuiltIn {
    BuiltIn,
}

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(Client::Table)
                    .add_column(boolean(ClientBuiltIn::BuiltIn).default(false))
                    .to_owned(),
            )
            .await?;

        manager
            .get_connection()
            .execute_unprepared(
                "UPDATE client SET built_in = TRUE WHERE name = 'Identity Account' AND description = 'Built-in account and session management application'",
            )
            .await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(Client::Table)
                    .drop_column(ClientBuiltIn::BuiltIn)
                    .to_owned(),
            )
            .await
    }
}
