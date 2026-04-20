use crate::m20260305_071904_create_user::User;
use sea_orm_migration::{prelude::*, schema::*};

#[derive(DeriveMigrationName)]
pub struct Migration;

#[derive(DeriveIden)]
pub enum Session {
    Table,
    Id,
    Oid,
    UserId,
    Status,
    Acr,
    AcrExpiresAt,
    DeviceName,
    DeviceType,
    OsName,
    OsVersion,
    BrowserName,
    BrowserVersion,
    UserAgent,
    IpAddress,
    Country,
    City,
    LastActiveAt,
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
                    .table(Session::Table)
                    .if_not_exists()
                    .col(pk_auto(Session::Id).big_integer())
                    .col(uuid_uniq(Session::Oid).default(Expr::cust("gen_random_uuid()")))
                    .col(big_integer(Session::UserId))
                    .col(string(Session::Status))
                    .col(string_null(Session::Acr))
                    .col(timestamp_with_time_zone_null(Session::AcrExpiresAt))
                    .col(string_null(Session::DeviceName))
                    .col(string_null(Session::DeviceType))
                    .col(string_null(Session::OsName))
                    .col(string_null(Session::OsVersion))
                    .col(string_null(Session::BrowserName))
                    .col(string_null(Session::BrowserVersion))
                    .col(string_null(Session::UserAgent))
                    .col(string_null(Session::IpAddress))
                    .col(string_null(Session::Country))
                    .col(string_null(Session::City))
                    .col(timestamp_with_time_zone(Session::LastActiveAt))
                    .col(timestamp_with_time_zone(Session::ExpiresAt))
                    .col(timestamp_with_time_zone_null(Session::RevokedAt))
                    .col(
                        timestamp_with_time_zone(Session::CreatedAt)
                            .default(Expr::current_timestamp()),
                    )
                    .col(timestamp_with_time_zone_null(Session::UpdatedAt))
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk_session_user_id")
                            .from(Session::Table, Session::UserId)
                            .to(User::Table, User::Id)
                            .on_delete(ForeignKeyAction::Cascade)
                            .on_update(ForeignKeyAction::Cascade),
                    )
                    .to_owned(),
            )
            .await?;
        manager
            .create_index(
                Index::create()
                    .table(Session::Table)
                    .name("idx_session_user_id")
                    .col(Session::UserId)
                    .to_owned(),
            )
            .await?;
        manager
            .create_index(
                Index::create()
                    .table(Session::Table)
                    .name("idx_session_status")
                    .col(Session::Status)
                    .to_owned(),
            )
            .await?;
        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_index(
                Index::drop()
                    .table(Session::Table)
                    .name("idx_session_status")
                    .to_owned(),
            )
            .await?;
        manager
            .drop_index(
                Index::drop()
                    .table(Session::Table)
                    .name("idx_session_user_id")
                    .to_owned(),
            )
            .await?;
        manager
            .drop_table(Table::drop().table(Session::Table).to_owned())
            .await?;
        Ok(())
    }
}
