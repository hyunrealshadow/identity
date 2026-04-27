use sea_orm_migration::{prelude::*, schema::*};

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
                    .col(timestamp(KeyJwk::CreatedAt))
                    .col(timestamp_null(KeyJwk::UpdatedAt))
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk_key_jwk_key_oid")
                            .from(KeyJwk::Table, KeyJwk::KeyOid)
                            .to(
                                super::m20260319_121151_create_key::Key::Table,
                                super::m20260319_121151_create_key::Key::Oid,
                            )
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
