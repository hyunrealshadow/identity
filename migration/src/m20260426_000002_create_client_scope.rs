use crate::{m20260306_031058_create_client::Client, m20260426_000001_create_scope::Scope};
use sea_orm_migration::{async_trait, sea_orm};
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
pub enum ClientScope {
    Table,
    Id,
    ClientId,
    ScopeId,
    CreatedAt,
}

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .create_table(
                Table::create()
                    .table(ClientScope::Table)
                    .if_not_exists()
                    .col(pk_auto(ClientScope::Id).big_integer())
                    .col(big_integer(ClientScope::ClientId))
                    .col(big_integer(ClientScope::ScopeId))
                    .col(
                        timestamp_with_time_zone(ClientScope::CreatedAt)
                            .default(Expr::current_timestamp()),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk_client_scope_client_id")
                            .from(ClientScope::Table, ClientScope::ClientId)
                            .to(Client::Table, Client::Id)
                            .on_delete(ForeignKeyAction::Cascade)
                            .on_update(ForeignKeyAction::Cascade),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk_client_scope_scope_id")
                            .from(ClientScope::Table, ClientScope::ScopeId)
                            .to(Scope::Table, Scope::Id)
                            .on_delete(ForeignKeyAction::Cascade)
                            .on_update(ForeignKeyAction::Cascade),
                    )
                    .to_owned(),
            )
            .await?;

        manager
            .create_index(
                Index::create()
                    .table(ClientScope::Table)
                    .name("idx_client_scope_client_scope")
                    .col(ClientScope::ClientId)
                    .col(ClientScope::ScopeId)
                    .unique()
                    .to_owned(),
            )
            .await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_index(
                Index::drop()
                    .table(ClientScope::Table)
                    .name("idx_client_scope_client_scope")
                    .to_owned(),
            )
            .await?;
        manager
            .drop_table(Table::drop().table(ClientScope::Table).to_owned())
            .await
    }
}
