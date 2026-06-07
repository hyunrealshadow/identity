use crate::m20260306_031058_create_client::Client;
use sea_orm_migration::{async_trait, sea_orm};
use sea_orm_migration::{
    prelude::{
        ConnectionTrait, DbErr, DeriveIden, DeriveMigrationName, Expr, ForeignKey,
        ForeignKeyAction, Index, MigrationTrait, SchemaManager, Table,
    },
    schema::{
        big_integer, json_binary, pk_auto, string, timestamp_with_time_zone,
        timestamp_with_time_zone_null, uuid_uniq,
    },
};

#[derive(DeriveMigrationName)]
pub struct Migration;

#[derive(DeriveIden)]
pub enum ClientAuthorization {
    Table,
    Id,
    Oid,
    ClientId,
    Type,
    Data,
    ExpiresAt,
    CompletedAt,
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
                    .table(ClientAuthorization::Table)
                    .if_not_exists()
                    .col(pk_auto(ClientAuthorization::Id).big_integer())
                    .col(
                        uuid_uniq(ClientAuthorization::Oid)
                            .default(Expr::cust("gen_random_uuid()")),
                    )
                    .col(big_integer(ClientAuthorization::ClientId))
                    .col(string(ClientAuthorization::Type))
                    .col(json_binary(ClientAuthorization::Data))
                    .col(timestamp_with_time_zone(ClientAuthorization::ExpiresAt))
                    .col(timestamp_with_time_zone_null(
                        ClientAuthorization::CompletedAt,
                    ))
                    .col(timestamp_with_time_zone_null(
                        ClientAuthorization::RevokedAt,
                    ))
                    .col(
                        timestamp_with_time_zone(ClientAuthorization::CreatedAt)
                            .default(Expr::current_timestamp()),
                    )
                    .col(timestamp_with_time_zone_null(
                        ClientAuthorization::UpdatedAt,
                    ))
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk_client_authorization_client_id")
                            .from(ClientAuthorization::Table, ClientAuthorization::ClientId)
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
                    .table(ClientAuthorization::Table)
                    .name("idx_client_authorization_client_id")
                    .col(ClientAuthorization::ClientId)
                    .to_owned(),
            )
            .await?;
        manager
            .create_index(
                Index::create()
                    .table(ClientAuthorization::Table)
                    .name("idx_client_authorization_type")
                    .col(ClientAuthorization::Type)
                    .to_owned(),
            )
            .await?;
        manager
            .create_index(
                Index::create()
                    .table(ClientAuthorization::Table)
                    .name("idx_client_authorization_expires_at")
                    .col(ClientAuthorization::ExpiresAt)
                    .to_owned(),
            )
            .await?;
        manager
            .get_connection()
            .execute_unprepared(
                r#"CREATE INDEX IF NOT EXISTS "idx_client_authorization_data_code_oid"
                   ON "client_authorization" (("data"->>'authorization_code_oid'))
                   WHERE "type" = 'access_token'"#,
            )
            .await?;
        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .get_connection()
            .execute_unprepared(r#"DROP INDEX IF EXISTS "idx_client_authorization_data_code_oid""#)
            .await?;
        manager
            .drop_index(
                Index::drop()
                    .table(ClientAuthorization::Table)
                    .name("idx_client_authorization_expires_at")
                    .to_owned(),
            )
            .await?;
        manager
            .drop_index(
                Index::drop()
                    .table(ClientAuthorization::Table)
                    .name("idx_client_authorization_type")
                    .to_owned(),
            )
            .await?;
        manager
            .drop_index(
                Index::drop()
                    .table(ClientAuthorization::Table)
                    .name("idx_client_authorization_client_id")
                    .to_owned(),
            )
            .await?;
        manager
            .drop_table(Table::drop().table(ClientAuthorization::Table).to_owned())
            .await?;
        Ok(())
    }
}
