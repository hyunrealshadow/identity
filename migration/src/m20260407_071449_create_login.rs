use crate::m20260305_071904_create_user::User;
use crate::m20260306_031058_create_client::Client;
use crate::m20260306_090746_create_session::Session;
use crate::m20260407_060938_create_client_authorization::ClientAuthorization;
use sea_orm_migration::{async_trait, sea_orm};
use sea_orm_migration::{
    prelude::{
        DbErr, DeriveIden, DeriveMigrationName, Expr, ForeignKey, ForeignKeyAction, Index,
        MigrationTrait, SchemaManager, Table,
    },
    schema::{
        big_integer, big_integer_null, integer, pk_auto, string, string_null,
        timestamp_with_time_zone, timestamp_with_time_zone_null, uuid_uniq,
    },
};

#[derive(DeriveMigrationName)]
pub struct Migration;

#[derive(DeriveIden)]
enum Login {
    Table,
    Id,
    Oid,
    ClientId,
    ClientAuthorizationId,
    SessionId,
    UserId,
    Status,
    FailureReason,
    FailedAttempts,
    Acr,
    RequestedAcr,
    CreatedAt,
    UpdatedAt,
}

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .create_table(
                Table::create()
                    .table(Login::Table)
                    .if_not_exists()
                    .col(pk_auto(Login::Id).big_integer())
                    .col(uuid_uniq(Login::Oid).default(Expr::cust("gen_random_uuid()")))
                    .col(big_integer(Login::ClientId))
                    .col(big_integer(Login::ClientAuthorizationId))
                    .col(big_integer_null(Login::SessionId))
                    .col(big_integer_null(Login::UserId))
                    .col(string(Login::Status))
                    .col(string_null(Login::FailureReason))
                    .col(integer(Login::FailedAttempts).default(0))
                    .col(string_null(Login::Acr))
                    .col(string_null(Login::RequestedAcr))
                    .col(
                        timestamp_with_time_zone(Login::CreatedAt)
                            .default(Expr::current_timestamp()),
                    )
                    .col(timestamp_with_time_zone_null(Login::UpdatedAt))
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk_login_client_id")
                            .from(Login::Table, Login::ClientId)
                            .to(Client::Table, Client::Id)
                            .on_delete(ForeignKeyAction::Cascade)
                            .on_update(ForeignKeyAction::Cascade),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk_login_client_authorization_id")
                            .from(Login::Table, Login::ClientAuthorizationId)
                            .to(ClientAuthorization::Table, ClientAuthorization::Id)
                            .on_delete(ForeignKeyAction::Cascade)
                            .on_update(ForeignKeyAction::Cascade),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk_login_session_id")
                            .from(Login::Table, Login::SessionId)
                            .to(Session::Table, Session::Id)
                            .on_delete(ForeignKeyAction::SetNull)
                            .on_update(ForeignKeyAction::Cascade),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk_login_user_id")
                            .from(Login::Table, Login::UserId)
                            .to(User::Table, User::Id)
                            .on_delete(ForeignKeyAction::Cascade),
                    )
                    .to_owned(),
            )
            .await?;
        manager
            .create_index(
                Index::create()
                    .table(Login::Table)
                    .name("idx_login_client_id")
                    .col(Login::ClientId)
                    .to_owned(),
            )
            .await?;
        manager
            .create_index(
                Index::create()
                    .table(Login::Table)
                    .name("idx_login_client_authorization_id")
                    .col(Login::ClientAuthorizationId)
                    .to_owned(),
            )
            .await?;
        manager
            .create_index(
                Index::create()
                    .table(Login::Table)
                    .name("idx_login_session_id")
                    .col(Login::SessionId)
                    .to_owned(),
            )
            .await?;
        manager
            .create_index(
                Index::create()
                    .table(Login::Table)
                    .name("idx_login_user_id")
                    .col(Login::UserId)
                    .to_owned(),
            )
            .await?;
        manager
            .create_index(
                Index::create()
                    .table(Login::Table)
                    .name("idx_login_status")
                    .col(Login::Status)
                    .to_owned(),
            )
            .await?;
        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_index(
                Index::drop()
                    .table(Login::Table)
                    .name("idx_login_client_id")
                    .to_owned(),
            )
            .await?;
        manager
            .drop_index(
                Index::drop()
                    .table(Login::Table)
                    .name("idx_login_client_authorization_id")
                    .to_owned(),
            )
            .await?;
        manager
            .drop_index(
                Index::drop()
                    .table(Login::Table)
                    .name("idx_login_session_id")
                    .to_owned(),
            )
            .await?;
        manager
            .drop_index(
                Index::drop()
                    .table(Login::Table)
                    .name("idx_login_user_id")
                    .to_owned(),
            )
            .await?;
        manager
            .drop_index(
                Index::drop()
                    .table(Login::Table)
                    .name("idx_login_status")
                    .to_owned(),
            )
            .await?;
        manager
            .drop_table(Table::drop().table(Login::Table).to_owned())
            .await?;
        Ok(())
    }
}
