use sea_orm_migration::{
    async_trait,
    prelude::{
        ConnectionTrait, DbErr, DeriveIden, DeriveMigrationName, Expr, ForeignKey,
        ForeignKeyAction, Index, MigrationTrait, SchemaManager, Table,
    },
    schema::{
        big_integer, boolean, json_binary, pk_auto, string, timestamp_with_time_zone,
        timestamp_with_time_zone_null, uuid_uniq,
    },
    sea_orm,
};

use crate::m20260306_031058_create_client::Client;

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
    IsExpired,
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
                    .col(boolean(ClientAuthorization::IsExpired).default(false))
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
        manager
            .get_connection()
            .execute_unprepared(
                r#"CREATE INDEX IF NOT EXISTS "idx_client_authorization_session_oid"
                   ON "client_authorization" (("data"->>'session_oid'))
                   WHERE "type" IN ('authorization_code', 'access_token', 'refresh_token')
                     AND "revoked_at" IS NULL"#,
            )
            .await?;
        for (name, field, type_) in [
            (
                "idx_client_authorization_device_code_digest",
                "device_code_digest",
                "device_authorization_request",
            ),
            (
                "idx_client_authorization_active_user_code",
                "user_code",
                "device_authorization_request",
            ),
            (
                "idx_client_authorization_device_authorization_user",
                "user_oid",
                "device_authorization",
            ),
            (
                "idx_client_authorization_refresh_token_rotated_from",
                "rotated_from",
                "refresh_token",
            ),
            (
                "idx_client_authorization_access_token_refresh_token_oid",
                "refresh_token_oid",
                "access_token",
            ),
            (
                "idx_client_authorization_access_token_device_authorization_oid",
                "device_authorization_oid",
                "access_token",
            ),
        ] {
            let unique = if matches!(field, "device_code_digest" | "user_code") {
                "UNIQUE "
            } else {
                ""
            };
            let active = if field == "user_code" {
                " AND \"is_expired\" = false AND \"completed_at\" IS NULL AND \"revoked_at\" IS NULL"
            } else {
                ""
            };
            manager
                .get_connection()
                .execute_unprepared(&format!(
                    "CREATE {unique}INDEX IF NOT EXISTS \"{name}\" ON \"client_authorization\" ((\"data\"->>'{field}')) WHERE \"type\" = '{type_}'{active}"
                ))
                .await?;
        }
        manager
            .get_connection()
            .execute_unprepared(
                r#"CREATE INDEX IF NOT EXISTS "idx_client_authorization_expiration_pending"
                   ON "client_authorization" ("expires_at")
                   WHERE "is_expired" = false"#,
            )
            .await?;
        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        for index in [
            "idx_client_authorization_expiration_pending",
            "idx_client_authorization_access_token_device_authorization_oid",
            "idx_client_authorization_access_token_refresh_token_oid",
            "idx_client_authorization_refresh_token_rotated_from",
            "idx_client_authorization_device_authorization_user",
            "idx_client_authorization_active_user_code",
            "idx_client_authorization_device_code_digest",
        ] {
            manager
                .get_connection()
                .execute_unprepared(&format!(r#"DROP INDEX IF EXISTS "{index}""#))
                .await?;
        }
        manager
            .get_connection()
            .execute_unprepared(r#"DROP INDEX IF EXISTS "idx_client_authorization_session_oid""#)
            .await?;
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
