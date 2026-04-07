use crate::m20260306_031058_create_client::Client;
use sea_orm_migration::{prelude::*, schema::*};

#[derive(DeriveMigrationName)]
pub struct Migration;

#[derive(DeriveIden)]
pub enum ClientOpenIdConnectCredential {
    Table,
    Id,
    Oid,
    ClientId,
    Type,
    Data,
    CreatedAt,
    UpdatedAt,
}

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .create_table(
                Table::create()
                    .table(ClientOpenIdConnectCredential::Table)
                    .if_not_exists()
                    .col(pk_auto(ClientOpenIdConnectCredential::Id).big_integer())
                    .col(
                        uuid_uniq(ClientOpenIdConnectCredential::Oid)
                            .default(Expr::cust("gen_random_uuid()")),
                    )
                    .col(big_integer(ClientOpenIdConnectCredential::ClientId))
                    .col(string(ClientOpenIdConnectCredential::Type))
                    .col(json_binary(ClientOpenIdConnectCredential::Data))
                    .col(
                        timestamp_with_time_zone(ClientOpenIdConnectCredential::CreatedAt)
                            .default(Expr::current_timestamp()),
                    )
                    .col(timestamp_with_time_zone_null(
                        ClientOpenIdConnectCredential::UpdatedAt,
                    ))
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk_client_open_id_connect_credential_client_id")
                            .from(
                                ClientOpenIdConnectCredential::Table,
                                ClientOpenIdConnectCredential::ClientId,
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
                    .table(ClientOpenIdConnectCredential::Table)
                    .name("idx_client_open_id_connect_credential_client_id")
                    .col(ClientOpenIdConnectCredential::ClientId)
                    .unique()
                    .to_owned(),
            )
            .await?;
        manager
            .create_index(
                Index::create()
                    .table(ClientOpenIdConnectCredential::Table)
                    .name("idx_client_open_id_connect_credential_type")
                    .col(ClientOpenIdConnectCredential::Type)
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
                    .table(ClientOpenIdConnectCredential::Table)
                    .name("idx_client_open_id_connect_credential_type")
                    .to_owned(),
            )
            .await?;
        manager
            .drop_index(
                Index::drop()
                    .table(ClientOpenIdConnectCredential::Table)
                    .name("idx_client_open_id_connect_credential_client_id")
                    .to_owned(),
            )
            .await?;
        manager
            .drop_table(
                Table::drop()
                    .table(ClientOpenIdConnectCredential::Table)
                    .to_owned(),
            )
            .await?;
        Ok(())
    }
}
