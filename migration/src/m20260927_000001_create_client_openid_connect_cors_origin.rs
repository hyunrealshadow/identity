use crate::m20260306_031058_create_client::Client;
use sea_orm_migration::{async_trait, sea_orm};
use sea_orm_migration::{
    prelude::{
        DbErr, DeriveIden, DeriveMigrationName, Expr, ForeignKey, ForeignKeyAction, Index,
        MigrationTrait, SchemaManager, Table,
    },
    schema::{big_integer, pk_auto, text, timestamp_with_time_zone, timestamp_with_time_zone_null},
};

#[derive(DeriveMigrationName)]
pub struct Migration;

#[derive(DeriveIden)]
enum ClientOpenIdConnectCorsOrigin {
    #[sea_orm(iden = "client_openid_connect_cors_origin")]
    Table,
    Id,
    ClientId,
    Origin,
    CreatedAt,
    UpdatedAt,
}

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .create_table(
                Table::create()
                    .table(ClientOpenIdConnectCorsOrigin::Table)
                    .if_not_exists()
                    .col(pk_auto(ClientOpenIdConnectCorsOrigin::Id).big_integer())
                    .col(big_integer(ClientOpenIdConnectCorsOrigin::ClientId))
                    .col(text(ClientOpenIdConnectCorsOrigin::Origin))
                    .col(
                        timestamp_with_time_zone(ClientOpenIdConnectCorsOrigin::CreatedAt)
                            .default(Expr::current_timestamp()),
                    )
                    .col(timestamp_with_time_zone_null(
                        ClientOpenIdConnectCorsOrigin::UpdatedAt,
                    ))
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk_client_openid_connect_cors_origin_client_id")
                            .from(
                                ClientOpenIdConnectCorsOrigin::Table,
                                ClientOpenIdConnectCorsOrigin::ClientId,
                            )
                            .to(Client::Table, Client::Id)
                            .on_delete(ForeignKeyAction::Cascade),
                    )
                    .to_owned(),
            )
            .await?;
        manager
            .create_index(
                Index::create()
                    .table(ClientOpenIdConnectCorsOrigin::Table)
                    .name("idx_client_openid_connect_cors_origin_client_id_origin")
                    .col(ClientOpenIdConnectCorsOrigin::ClientId)
                    .col(ClientOpenIdConnectCorsOrigin::Origin)
                    .unique()
                    .to_owned(),
            )
            .await?;
        manager
            .create_index(
                Index::create()
                    .table(ClientOpenIdConnectCorsOrigin::Table)
                    .name("idx_client_openid_connect_cors_origin_origin")
                    .col(ClientOpenIdConnectCorsOrigin::Origin)
                    .to_owned(),
            )
            .await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_index(
                Index::drop()
                    .table(ClientOpenIdConnectCorsOrigin::Table)
                    .name("idx_client_openid_connect_cors_origin_client_id_origin")
                    .to_owned(),
            )
            .await?;
        manager
            .drop_index(
                Index::drop()
                    .table(ClientOpenIdConnectCorsOrigin::Table)
                    .name("idx_client_openid_connect_cors_origin_origin")
                    .to_owned(),
            )
            .await?;
        manager
            .drop_table(
                Table::drop()
                    .table(ClientOpenIdConnectCorsOrigin::Table)
                    .to_owned(),
            )
            .await?;
        Ok(())
    }
}
