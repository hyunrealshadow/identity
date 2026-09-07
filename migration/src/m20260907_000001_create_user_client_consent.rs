use crate::{
    m20260305_071904_create_user::User, m20260306_031058_create_client::Client,
    m20260426_000001_create_scope::Scope,
};
use sea_orm_migration::sea_orm;
use sea_orm_migration::{
    prelude::{
        DbErr, DeriveIden, DeriveMigrationName, Expr, ForeignKey, ForeignKeyAction, Index,
        MigrationTrait, SchemaManager, Table,
    },
    schema::{big_integer, pk_auto, timestamp_with_time_zone},
};

#[derive(DeriveMigrationName)]
pub struct Migration;

#[derive(DeriveIden)]
enum UserClientConsent {
    Table,
    Id,
    UserId,
    ClientId,
    ScopeId,
    ApprovedAt,
}

#[sea_orm_migration::async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .create_table(
                Table::create()
                    .table(UserClientConsent::Table)
                    .if_not_exists()
                    .col(pk_auto(UserClientConsent::Id).big_integer())
                    .col(big_integer(UserClientConsent::UserId))
                    .col(big_integer(UserClientConsent::ClientId))
                    .col(big_integer(UserClientConsent::ScopeId))
                    .col(
                        timestamp_with_time_zone(UserClientConsent::ApprovedAt)
                            .default(Expr::current_timestamp()),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk_user_client_consent_user_id")
                            .from(UserClientConsent::Table, UserClientConsent::UserId)
                            .to(User::Table, User::Id)
                            .on_delete(ForeignKeyAction::Cascade)
                            .on_update(ForeignKeyAction::Cascade),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk_user_client_consent_scope_id")
                            .from(UserClientConsent::Table, UserClientConsent::ScopeId)
                            .to(Scope::Table, Scope::Id)
                            .on_delete(ForeignKeyAction::Cascade)
                            .on_update(ForeignKeyAction::Cascade),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk_user_client_consent_client_id")
                            .from(UserClientConsent::Table, UserClientConsent::ClientId)
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
                    .table(UserClientConsent::Table)
                    .name("idx_user_client_consent_unique_scope_id")
                    .col(UserClientConsent::UserId)
                    .col(UserClientConsent::ClientId)
                    .col(UserClientConsent::ScopeId)
                    .unique()
                    .to_owned(),
            )
            .await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(Table::drop().table(UserClientConsent::Table).to_owned())
            .await
    }
}
