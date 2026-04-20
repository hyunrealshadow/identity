use crate::m20260306_031058_create_client::Client;
use sea_orm_migration::{prelude::*, schema::*};

#[derive(DeriveMigrationName)]
pub struct Migration;

#[derive(DeriveIden)]
pub enum ClientRequest {
    Table,
    Id,
    Oid,
    ClientId,
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
                    .table(ClientRequest::Table)
                    .if_not_exists()
                    .col(pk_auto(ClientRequest::Id).big_integer())
                    .col(uuid_uniq(ClientRequest::Oid).default(Expr::cust("gen_random_uuid()")))
                    .col(big_integer(ClientRequest::ClientId))
                    .col(string(ClientRequest::Type))
                    .col(json_binary(ClientRequest::Data))
                    .col(timestamp_with_time_zone(ClientRequest::ExpiresAt))
                    .col(timestamp_with_time_zone_null(ClientRequest::RevokedAt))
                    .col(
                        timestamp_with_time_zone(ClientRequest::CreatedAt)
                            .default(Expr::current_timestamp()),
                    )
                    .col(timestamp_with_time_zone_null(ClientRequest::UpdatedAt))
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk_client_request_client_id")
                            .from(ClientRequest::Table, ClientRequest::ClientId)
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
                    .table(ClientRequest::Table)
                    .name("idx_client_request_client_id")
                    .col(ClientRequest::ClientId)
                    .to_owned(),
            )
            .await?;
        manager
            .create_index(
                Index::create()
                    .table(ClientRequest::Table)
                    .name("idx_client_request_type")
                    .col(ClientRequest::Type)
                    .to_owned(),
            )
            .await?;
        manager
            .create_index(
                Index::create()
                    .table(ClientRequest::Table)
                    .name("idx_client_request_expires_at")
                    .col(ClientRequest::ExpiresAt)
                    .to_owned(),
            )
            .await?;
        // Expression index on JSON token field for refresh token lookup.
        manager
            .get_connection()
            .execute_unprepared(
                r#"CREATE INDEX IF NOT EXISTS "idx_client_request_data_token"
                   ON "client_request" (("data"->>'token'))
                   WHERE "type" = 'refresh_token'"#,
            )
            .await?;
        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .get_connection()
            .execute_unprepared(r#"DROP INDEX IF EXISTS "idx_client_request_data_token""#)
            .await?;
        manager
            .drop_index(
                Index::drop()
                    .table(ClientRequest::Table)
                    .name("idx_client_request_expires_at")
                    .to_owned(),
            )
            .await?;
        manager
            .drop_index(
                Index::drop()
                    .table(ClientRequest::Table)
                    .name("idx_client_request_type")
                    .to_owned(),
            )
            .await?;
        manager
            .drop_index(
                Index::drop()
                    .table(ClientRequest::Table)
                    .name("idx_client_request_client_id")
                    .to_owned(),
            )
            .await?;
        manager
            .drop_table(Table::drop().table(ClientRequest::Table).to_owned())
            .await?;
        Ok(())
    }
}
