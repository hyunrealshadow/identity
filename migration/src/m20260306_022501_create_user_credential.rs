use crate::m20260305_071904_create_user::User;
use sea_orm_migration::{prelude::*, schema::*};

#[derive(DeriveMigrationName)]
pub struct Migration;

#[derive(DeriveIden)]
pub enum UserCredential {
    Table,
    Id,
    Oid,
    UserId,
    Type,
    Data,
    CreatedAt,
    UpdatedAt,
}

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .create_table(
                Table::create()
                    .table(UserCredential::Table)
                    .if_not_exists()
                    .col(pk_auto(UserCredential::Id).big_integer())
                    .col(uuid_uniq(UserCredential::Oid).default(Expr::cust("gen_random_uuid()")))
                    .col(big_integer(UserCredential::UserId))
                    .col(string(UserCredential::Type))
                    .col(json_binary(UserCredential::Data))
                    .col(
                        timestamp_with_time_zone(UserCredential::CreatedAt)
                            .default(Expr::current_timestamp()),
                    )
                    .col(timestamp_with_time_zone_null(UserCredential::UpdatedAt))
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk_user_credential_user_id")
                            .from(UserCredential::Table, UserCredential::UserId)
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
                    .table(UserCredential::Table)
                    .name("idx_user_credential_type")
                    .col(UserCredential::Type)
                    .to_owned(),
            )
            .await?;
        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_index(
                Index::drop()
                    .table(UserCredential::Table)
                    .name("idx_user_credential_type")
                    .to_owned(),
            )
            .await?;
        manager
            .drop_table(Table::drop().table(UserCredential::Table).to_owned())
            .await?;
        Ok(())
    }
}
