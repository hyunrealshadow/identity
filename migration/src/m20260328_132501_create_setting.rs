use sea_orm_migration::{prelude::*, schema::*};

#[derive(DeriveMigrationName)]
pub struct Migration;

#[derive(DeriveIden)]
pub enum Setting {
    Table,
    Id,
    Oid,
    Key,
    Value,
    CreatedAt,
    UpdatedAt,
}

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .create_table(
                Table::create()
                    .table(Setting::Table)
                    .if_not_exists()
                    .col(pk_auto(Setting::Id))
                    .col(uuid_uniq(Setting::Oid))
                    .col(string_uniq(Setting::Key))
                    .col(json_binary(Setting::Value))
                    .col(timestamp(Setting::CreatedAt))
                    .col(timestamp_null(Setting::UpdatedAt))
                    .to_owned(),
            )
            .await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(Table::drop().table(Setting::Table).to_owned())
            .await
    }
}
