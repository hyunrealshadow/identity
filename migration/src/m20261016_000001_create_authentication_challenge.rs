use sea_orm_migration::sea_orm;
use sea_orm_migration::{
    async_trait,
    prelude::{
        Alias, ColumnDef, ConditionalStatement, DbErr, DeriveIden, DeriveMigrationName, Expr,
        ExprTrait, ForeignKey, ForeignKeyAction, Func, Index, MigrationTrait, SchemaManager, Table,
    },
    schema::{
        big_integer_null, integer, json_binary, pk_auto, string_null, timestamp_with_time_zone,
        timestamp_with_time_zone_null, uuid_uniq,
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
    TokenDigest,
    SentAt,
    SendCount,
    WindowStartedAt,
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
                    .col(big_integer_null(AuthenticationChallenge::UserId))
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
                    // SHA-256 of an emailed link token, base64url, for links
                    // that are followed without an interaction.
                    .col(string_null(AuthenticationChallenge::TokenDigest))
                    // What an outbound challenge has sent so far.
                    .col(timestamp_with_time_zone_null(
                        AuthenticationChallenge::SentAt,
                    ))
                    .col(integer(AuthenticationChallenge::SendCount).default(0))
                    .col(timestamp_with_time_zone_null(
                        AuthenticationChallenge::WindowStartedAt,
                    ))
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
                    // A challenge belongs to a login, a session, or, when it
                    // is followed without either, to its account alone.
                    .check(Check::named(
                        "authentication_challenge_one_binding",
                        Expr::from(Func::cust(Alias::new("num_nonnulls")).args([
                            Expr::col(AuthenticationChallenge::LoginId),
                            Expr::col(AuthenticationChallenge::SessionId),
                        ]))
                        .lte(1)
                        .and(
                            Expr::from(Func::cust(Alias::new("num_nonnulls")).args([
                                Expr::col(AuthenticationChallenge::LoginId),
                                Expr::col(AuthenticationChallenge::SessionId),
                                Expr::col(AuthenticationChallenge::UserId),
                            ]))
                            .gte(1),
                        ),
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
                    .name("idx_authentication_challenge_token_digest_unique")
                    .table(AuthenticationChallenge::Table)
                    .unique()
                    .col(AuthenticationChallenge::TokenDigest)
                    .and_where(Expr::col(AuthenticationChallenge::TokenDigest).is_not_null())
                    .to_owned(),
            )
            .await?;
        // An account has at most one outstanding challenge of each purpose
        // that is bound to it alone, such as an email verification.
        manager
            .create_index(
                Index::create()
                    .name("idx_authentication_challenge_account_purpose_unique")
                    .table(AuthenticationChallenge::Table)
                    .unique()
                    .col(AuthenticationChallenge::UserId)
                    .col(AuthenticationChallenge::Purpose)
                    .and_where(
                        Expr::col(AuthenticationChallenge::LoginId)
                            .is_null()
                            .and(Expr::col(AuthenticationChallenge::SessionId).is_null()),
                    )
                    .to_owned(),
            )
            .await?;

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
