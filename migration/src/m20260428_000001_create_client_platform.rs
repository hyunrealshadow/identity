use crate::m20260306_031058_create_client::Client;
use sea_orm_migration::{async_trait, sea_orm};
use sea_orm_migration::{
    prelude::{
        DbErr, DeriveIden, DeriveMigrationName, Expr, ForeignKey, ForeignKeyAction, Index,
        MigrationTrait, SchemaManager, Table,
    },
    schema::{
        big_integer, json_binary_null, pk_auto, string, timestamp_with_time_zone,
        timestamp_with_time_zone_null,
    },
};

#[derive(DeriveMigrationName)]
pub struct Migration;

#[derive(DeriveIden)]
pub enum ClientPlatform {
    Table,
    Id,
    ClientId,
    Platform,
    RedirectUris,
    CreatedAt,
    UpdatedAt,
}

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .create_table(
                Table::create()
                    .table(ClientPlatform::Table)
                    .if_not_exists()
                    .col(pk_auto(ClientPlatform::Id).big_integer())
                    .col(big_integer(ClientPlatform::ClientId))
                    .col(string(ClientPlatform::Platform))
                    .col(json_binary_null(ClientPlatform::RedirectUris))
                    .col(
                        timestamp_with_time_zone(ClientPlatform::CreatedAt)
                            .default(Expr::current_timestamp()),
                    )
                    .col(timestamp_with_time_zone_null(ClientPlatform::UpdatedAt))
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk_client_platform_client_id")
                            .from(ClientPlatform::Table, ClientPlatform::ClientId)
                            .to(Client::Table, Client::Id)
                            .on_delete(ForeignKeyAction::Cascade)
                            .on_update(ForeignKeyAction::Cascade),
                    )
                    .to_owned(),
            )
            .await?;

        manager
            .create_index(
                Index::create()
                    .table(ClientPlatform::Table)
                    .name("idx_client_platform_client_id_platform")
                    .col(ClientPlatform::ClientId)
                    .col(ClientPlatform::Platform)
                    .unique()
                    .to_owned(),
            )
            .await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_index(
                Index::drop()
                    .table(ClientPlatform::Table)
                    .name("idx_client_platform_client_id_platform")
                    .to_owned(),
            )
            .await?;

        manager
            .drop_table(Table::drop().table(ClientPlatform::Table).to_owned())
            .await?;

        Ok(())
    }
}
