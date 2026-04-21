use sea_orm_migration::{prelude::*, schema::*};

#[derive(DeriveMigrationName)]
pub struct Migration;

#[derive(DeriveIden)]
pub enum Key {
    Table,
    Id,
    Oid,
    Type,
    Data,
    ExpiresAt,
    RevokedAt,
    CreatedAt,
    UpdatedAt,
}

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .create_table(
                Table::create()
                    .table(Key::Table)
                    .if_not_exists()
                    .col(pk_auto(Key::Id))
                    .col(uuid_uniq(Key::Oid))
                    .col(string(Key::Type))
                    .col(json_binary(Key::Data))
                    .col(timestamp_with_time_zone(Key::ExpiresAt))
                    .col(timestamp_with_time_zone_null(Key::RevokedAt))
                    .col(timestamp(Key::CreatedAt))
                    .col(timestamp_null(Key::UpdatedAt))
                    .to_owned(),
            )
            .await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(Table::drop().table(Key::Table).to_owned())
            .await
    }
}
