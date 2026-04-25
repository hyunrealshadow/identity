use sea_orm_migration::{prelude::*, schema::*};

#[derive(DeriveMigrationName)]
pub struct Migration;

#[derive(DeriveIden)]
pub enum User {
    Table,
    Id,
    Oid,
    Email,
    EmailNormalized,
    Name,
    NameNormalized,
    GivenName,
    FamilyName,
    MiddleName,
    Nickname,
    Profile,
    Picture,
    Website,
    Gender,
    Birthdate,
    Zoneinfo,
    Locale,
    EmailVerified,
    FailedAttempts,
    Enabled,
    Locked,
    LockedUntil,
    CreatedAt,
    UpdatedAt,
}

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .create_table(
                Table::create()
                    .table(User::Table)
                    .if_not_exists()
                    .col(pk_auto(User::Id).big_integer())
                    .col(uuid_uniq(User::Oid).default(Expr::cust("gen_random_uuid()")))
                    .col(string(User::Email))
                    .col(string_uniq(User::EmailNormalized))
                    .col(string(User::Name))
                    .col(string_uniq(User::NameNormalized))
                    .col(string_null(User::GivenName))
                    .col(string_null(User::FamilyName))
                    .col(string_null(User::MiddleName))
                    .col(string_null(User::Nickname))
                    .col(string_null(User::Profile))
                    .col(string_null(User::Picture))
                    .col(string_null(User::Website))
                    .col(string_null(User::Gender))
                    .col(string_null(User::Birthdate))
                    .col(string_null(User::Zoneinfo))
                    .col(string_null(User::Locale))
                    .col(boolean(User::EmailVerified).default(false))
                    .col(integer(User::FailedAttempts).default(0))
                    .col(boolean(User::Enabled).default(true))
                    .col(boolean(User::Locked).default(false))
                    .col(timestamp_with_time_zone_null(User::LockedUntil))
                    .col(
                        timestamp_with_time_zone(User::CreatedAt)
                            .default(Expr::current_timestamp()),
                    )
                    .col(timestamp_with_time_zone_null(User::UpdatedAt))
                    .to_owned(),
            )
            .await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(Table::drop().table(User::Table).to_owned())
            .await
    }
}
