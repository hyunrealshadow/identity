use sea_orm_migration::sea_orm;
use sea_orm_migration::{
    async_trait,
    prelude::{
        Alias, ColumnDef, ConditionalStatement, DbErr, DeriveIden, DeriveMigrationName, Expr,
        ExprTrait, ForeignKey, ForeignKeyAction, Func, Index, MigrationTrait, SchemaManager, Table,
    },
    schema::{
        big_integer, big_integer_null, json_binary, pk_auto, timestamp_with_time_zone, uuid_uniq,
    },
    sea_orm::sea_query::{Check, extension::postgres::PgExpr},
};

use crate::{
    m20260305_071904_create_user::User, m20260306_022501_create_user_credential::UserCredential,
    m20260306_090746_create_session::Session, m20260407_071449_create_login::Login,
};

#[derive(DeriveMigrationName)]
pub struct Migration;

#[derive(DeriveIden)]
enum AuthenticationChallenge {
    Table,
    Id,
    Oid,
    UserId,
    LoginId,
    SessionId,
    Method,
    Purpose,
    State,
    ExpiresAt,
    CreatedAt,
}

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .create_table(
                Table::create()
                    .table(AuthenticationChallenge::Table)
                    .col(pk_auto(AuthenticationChallenge::Id).big_integer())
                    .col(
                        uuid_uniq(AuthenticationChallenge::Oid)
                            .default(Func::cust(Alias::new("gen_random_uuid"))),
                    )
                    .col(big_integer(AuthenticationChallenge::UserId))
                    .col(big_integer_null(AuthenticationChallenge::LoginId))
                    .col(big_integer_null(AuthenticationChallenge::SessionId))
                    .col(
                        ColumnDef::new(AuthenticationChallenge::Method)
                            .string_len(32)
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(AuthenticationChallenge::Purpose)
                            .string_len(64)
                            .not_null(),
                    )
                    .col(json_binary(AuthenticationChallenge::State))
                    .col(timestamp_with_time_zone(AuthenticationChallenge::ExpiresAt))
                    .col(
                        timestamp_with_time_zone(AuthenticationChallenge::CreatedAt)
                            .default(Expr::current_timestamp()),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk_authentication_challenge_user")
                            .from(
                                AuthenticationChallenge::Table,
                                AuthenticationChallenge::UserId,
                            )
                            .to(User::Table, User::Id)
                            .on_delete(ForeignKeyAction::Cascade),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk_authentication_challenge_login")
                            .from(
                                AuthenticationChallenge::Table,
                                AuthenticationChallenge::LoginId,
                            )
                            .to(Login::Table, Login::Id)
                            .on_delete(ForeignKeyAction::Cascade),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk_authentication_challenge_session")
                            .from(
                                AuthenticationChallenge::Table,
                                AuthenticationChallenge::SessionId,
                            )
                            .to(Session::Table, Session::Id)
                            .on_delete(ForeignKeyAction::Cascade),
                    )
                    .check(Check::named(
                        "authentication_challenge_one_binding",
                        Expr::from(Func::cust(Alias::new("num_nonnulls")).args([
                            Expr::col(AuthenticationChallenge::LoginId),
                            Expr::col(AuthenticationChallenge::SessionId),
                        ]))
                        .eq(1),
                    ))
                    .to_owned(),
            )
            .await?;

        for (name, column) in [
            (
                "idx_authentication_challenge_login",
                AuthenticationChallenge::LoginId,
            ),
            (
                "idx_authentication_challenge_session",
                AuthenticationChallenge::SessionId,
            ),
            (
                "idx_authentication_challenge_user",
                AuthenticationChallenge::UserId,
            ),
            (
                "idx_authentication_challenge_expiry",
                AuthenticationChallenge::ExpiresAt,
            ),
        ] {
            manager
                .create_index(
                    Index::create()
                        .name(name)
                        .table(AuthenticationChallenge::Table)
                        .col(column)
                        .to_owned(),
                )
                .await?;
        }

        manager
            .create_index(
                Index::create()
                    .name("idx_user_credential_passkey_id")
                    .table(UserCredential::Table)
                    .unique()
                    .col(Expr::col(UserCredential::Data).cast_json_field("credential_id"))
                    .and_where(Expr::col(UserCredential::Type).eq("passkey"))
                    .to_owned(),
            )
            .await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_index(
                Index::drop()
                    .name("idx_user_credential_passkey_id")
                    .table(UserCredential::Table)
                    .to_owned(),
            )
            .await?;
        manager
            .drop_table(
                Table::drop()
                    .table(AuthenticationChallenge::Table)
                    .to_owned(),
            )
            .await?;
        Ok(())
    }
}
