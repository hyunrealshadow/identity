use sea_orm_migration::{
    async_trait,
    prelude::{
        DbErr, DeriveIden, DeriveMigrationName, ForeignKey, ForeignKeyAction, MigrationTrait,
        SchemaManager, Table,
    },
    schema::{
        json_binary, pk_auto, string, timestamp_with_time_zone, timestamp_with_time_zone_null,
        uuid, uuid_uniq,
    },
    sea_orm,
};

use super::m20260319_121151_create_key::Key;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[derive(DeriveIden)]
pub enum KeyJwk {
    Table,
    Id,
    Oid,
    KeyOid,
    Algorithm,
    Jwk,
    CreatedAt,
    UpdatedAt,
}

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .create_table(
                Table::create()
                    .table(KeyJwk::Table)
                    .if_not_exists()
                    .col(pk_auto(KeyJwk::Id))
                    .col(uuid_uniq(KeyJwk::Oid))
                    .col(uuid(KeyJwk::KeyOid))
                    .col(string(KeyJwk::Algorithm))
                    .col(json_binary(KeyJwk::Jwk))
                    .col(timestamp_with_time_zone(KeyJwk::CreatedAt))
                    .col(timestamp_with_time_zone_null(KeyJwk::UpdatedAt))
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk_key_jwk_key_oid")
                            .from(KeyJwk::Table, KeyJwk::KeyOid)
                            .to(Key::Table, Key::Oid)
                            .on_delete(ForeignKeyAction::Cascade),
                    )
                    .to_owned(),
            )
            .await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(Table::drop().table(KeyJwk::Table).to_owned())
            .await
    }
}
