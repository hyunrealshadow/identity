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
pub enum ClientOpenIdConnectPlatform {
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
                    .table(ClientOpenIdConnectPlatform::Table)
                    .if_not_exists()
                    .col(pk_auto(ClientOpenIdConnectPlatform::Id).big_integer())
                    .col(big_integer(ClientOpenIdConnectPlatform::ClientId))
                    .col(string(ClientOpenIdConnectPlatform::Platform))
                    .col(json_binary_null(ClientOpenIdConnectPlatform::RedirectUris))
                    .col(
                        timestamp_with_time_zone(ClientOpenIdConnectPlatform::CreatedAt)
                            .default(Expr::current_timestamp()),
                    )
                    .col(timestamp_with_time_zone_null(
                        ClientOpenIdConnectPlatform::UpdatedAt,
                    ))
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk_client_openid_connect_platform_client_id")
                            .from(
                                ClientOpenIdConnectPlatform::Table,
                                ClientOpenIdConnectPlatform::ClientId,
                            )
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
                    .table(ClientOpenIdConnectPlatform::Table)
                    .name("idx_client_openid_connect_platform_client_id_platform")
                    .col(ClientOpenIdConnectPlatform::ClientId)
                    .col(ClientOpenIdConnectPlatform::Platform)
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
                    .table(ClientOpenIdConnectPlatform::Table)
                    .name("idx_client_openid_connect_platform_client_id_platform")
                    .to_owned(),
            )
            .await?;

        manager
            .drop_table(
                Table::drop()
                    .table(ClientOpenIdConnectPlatform::Table)
                    .to_owned(),
            )
            .await?;

        Ok(())
    }
}
