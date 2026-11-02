use sea_orm_migration::prelude::Alias;
use sea_orm_migration::prelude::Func;
use sea_orm_migration::{
    async_trait,
    prelude::{
        ConditionalStatement, DbErr, DeriveIden, DeriveMigrationName, Expr, ExprTrait, ForeignKey,
        ForeignKeyAction, Index, MigrationTrait, SchemaManager, Table,
    },
    schema::{
        big_integer, boolean, json_binary, pk_auto, string, timestamp_with_time_zone,
        timestamp_with_time_zone_null, uuid_uniq,
    },
    sea_orm::{self, sea_query::extension::postgres::PgExpr},
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
                            .default(Func::cust(Alias::new("gen_random_uuid"))),
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
            .create_index(
                Index::create()
                    .name("idx_client_authorization_data_code_oid")
                    .table(ClientAuthorization::Table)
                    .col(
                        Expr::col(ClientAuthorization::Data)
                            .cast_json_field("authorization_code_oid"),
                    )
                    .and_where(Expr::col(ClientAuthorization::Type).eq("access_token"))
                    .to_owned(),
            )
            .await?;
        manager
            .create_index(
                Index::create()
                    .name("idx_client_authorization_session_oid")
                    .table(ClientAuthorization::Table)
                    .col(Expr::col(ClientAuthorization::Data).cast_json_field("session_oid"))
                    .and_where(Expr::col(ClientAuthorization::Type).is_in([
                        "authorization_code",
                        "access_token",
                        "refresh_token",
                    ]))
                    .and_where(Expr::col(ClientAuthorization::RevokedAt).is_null())
                    .to_owned(),
            )
            .await?;
        for (name, field, type_, unique) in [
            (
                "idx_client_authorization_par_digest",
                "request_uri_digest",
                "pushed_authorization_request",
                true,
            ),
            (
                "idx_client_authorization_device_code_digest",
                "device_code_digest",
                "device_authorization_request",
                true,
            ),
            (
                "idx_client_authorization_active_user_code",
                "user_code",
                "device_authorization_request",
                true,
            ),
            (
                "idx_client_authorization_device_authorization_user",
                "user_oid",
                "device_authorization",
                false,
            ),
            (
                "idx_client_authorization_refresh_token_rotated_from",
                "rotated_from",
                "refresh_token",
                false,
            ),
            (
                "idx_client_authorization_access_token_refresh_token_oid",
                "refresh_token_oid",
                "access_token",
                false,
            ),
            (
                "idx_client_authorization_access_token_device_authorization_oid",
                "device_authorization_oid",
                "access_token",
                false,
            ),
        ] {
            let mut index = Index::create();
            index
                .name(name)
                .table(ClientAuthorization::Table)
                .col(Expr::col(ClientAuthorization::Data).cast_json_field(field))
                .and_where(Expr::col(ClientAuthorization::Type).eq(type_));
            if unique {
                index.unique();
            }
            if field == "user_code" {
                index
                    .and_where(Expr::col(ClientAuthorization::IsExpired).eq(false))
                    .and_where(Expr::col(ClientAuthorization::CompletedAt).is_null())
                    .and_where(Expr::col(ClientAuthorization::RevokedAt).is_null());
            }
            manager.create_index(index).await?;
        }
        manager
            .create_index(
                Index::create()
                    .name("idx_client_authorization_expiration_pending")
                    .table(ClientAuthorization::Table)
                    .col(ClientAuthorization::ExpiresAt)
                    .and_where(Expr::col(ClientAuthorization::IsExpired).eq(false))
                    .to_owned(),
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
            "idx_client_authorization_par_digest",
            "idx_client_authorization_session_oid",
            "idx_client_authorization_data_code_oid",
        ] {
            manager
                .drop_index(
                    Index::drop()
                        .name(index)
                        .table(ClientAuthorization::Table)
                        .to_owned(),
                )
                .await?;
        }
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
