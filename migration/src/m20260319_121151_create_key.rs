use sea_orm_migration::{
    async_trait,
    prelude::{
        DbErr, DeriveIden, DeriveMigrationName, Index, MigrationTrait, SchemaManager, Table,
    },
    schema::{
        json_binary, pk_auto, string, timestamp_with_time_zone, timestamp_with_time_zone_null,
        uuid_null, uuid_uniq,
    },
    sea_orm,
};

#[derive(DeriveMigrationName)]
pub struct Migration;

#[derive(DeriveIden)]
pub enum Key {
    Table,
    Id,
    Oid,
    Type,
    Data,
    RotatedFromOid,
    RotatedAt,
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
                    .col(uuid_null(Key::RotatedFromOid))
                    .col(timestamp_with_time_zone_null(Key::RotatedAt))
                    .col(timestamp_with_time_zone(Key::ExpiresAt))
                    .col(timestamp_with_time_zone_null(Key::RevokedAt))
                    .col(timestamp_with_time_zone(Key::CreatedAt))
                    .col(timestamp_with_time_zone_null(Key::UpdatedAt))
                    .to_owned(),
            )
            .await?;
        manager
            .create_index(
                Index::create()
                    .name("key_rotated_from_oid_unique")
                    .table(Key::Table)
                    .col(Key::RotatedFromOid)
                    .unique()
                    .to_owned(),
            )
            .await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_index(
                Index::drop()
                    .name("key_rotated_from_oid_unique")
                    .table(Key::Table)
                    .to_owned(),
            )
            .await?;
        manager
            .drop_table(Table::drop().table(Key::Table).to_owned())
            .await
    }
}
