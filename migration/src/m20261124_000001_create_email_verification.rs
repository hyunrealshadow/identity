use sea_orm_migration::sea_orm;
use sea_orm_migration::{
    async_trait,
    prelude::{
        Alias, DbErr, DeriveIden, DeriveMigrationName, Expr, ForeignKey, ForeignKeyAction, Func,
        Index, MigrationTrait, SchemaManager, Table,
    },
    schema::{
        big_integer_uniq, integer, pk_auto, string, string_uniq, timestamp_with_time_zone,
        uuid_uniq,
    },
};

use crate::m20260305_071904_create_user::User;

#[derive(DeriveMigrationName)]
pub struct Migration;

/// The one outstanding email verification of an account: the address being
/// verified, the address the account had when it was requested, and the
/// digest of the emailed link token.
#[derive(DeriveIden)]
enum EmailVerification {
    Table,
    Id,
    Oid,
    UserId,
    Email,
    EmailNormalized,
    CurrentEmailNormalized,
    TokenDigest,
    SendCount,
    WindowStartedAt,
    SentAt,
    ExpiresAt,
    CreatedAt,
}

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .create_table(
                Table::create()
                    .table(EmailVerification::Table)
                    .col(pk_auto(EmailVerification::Id).big_integer())
                    .col(
                        uuid_uniq(EmailVerification::Oid)
                            .default(Func::cust(Alias::new("gen_random_uuid"))),
                    )
                    .col(big_integer_uniq(EmailVerification::UserId))
                    .col(string(EmailVerification::Email))
                    .col(string(EmailVerification::EmailNormalized))
                    // The account's address when the verification was
                    // requested; any later change voids the link.
                    .col(string(EmailVerification::CurrentEmailNormalized))
                    // SHA-256 of the link token, base64url.
                    .col(string_uniq(EmailVerification::TokenDigest))
                    .col(integer(EmailVerification::SendCount))
                    .col(timestamp_with_time_zone(EmailVerification::WindowStartedAt))
                    .col(timestamp_with_time_zone(EmailVerification::SentAt))
                    .col(timestamp_with_time_zone(EmailVerification::ExpiresAt))
                    .col(
                        timestamp_with_time_zone(EmailVerification::CreatedAt)
                            .default(Expr::current_timestamp()),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk_email_verification_user")
                            .from(EmailVerification::Table, EmailVerification::UserId)
                            .to(User::Table, User::Id)
                            .on_delete(ForeignKeyAction::Cascade),
                    )
                    .to_owned(),
            )
            .await?;

        manager
            .create_index(
                Index::create()
                    .name("idx_email_verification_expiry")
                    .table(EmailVerification::Table)
                    .col(EmailVerification::ExpiresAt)
                    .to_owned(),
            )
            .await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(Table::drop().table(EmailVerification::Table).to_owned())
            .await
    }
}
