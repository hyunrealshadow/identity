use sea_orm_migration::sea_orm;
use sea_orm_migration::{
    async_trait,
    prelude::{
        DbErr, DeriveIden, DeriveMigrationName, Expr, ForeignKey, ForeignKeyAction, Index,
        MigrationTrait, SchemaManager, Table,
    },
    schema::{big_integer, pk_auto, timestamp_with_time_zone, uuid_uniq},
};

use crate::{m20260426_000001_create_scope::Scope, m20261022_000005_create_role::Role};

#[derive(DeriveMigrationName)]
pub struct Migration;

#[derive(DeriveIden)]
pub enum RolePermission {
    Table,
    Id,
    Oid,
    RoleId,
    ScopeId,
    CreatedAt,
}

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .create_table(
                Table::create()
                    .table(RolePermission::Table)
                    .col(pk_auto(RolePermission::Id).big_integer())
                    .col(uuid_uniq(RolePermission::Oid))
                    .col(big_integer(RolePermission::RoleId))
                    .col(big_integer(RolePermission::ScopeId))
                    .col(
                        timestamp_with_time_zone(RolePermission::CreatedAt)
                            .default(Expr::current_timestamp()),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk_role_permission_role")
                            .from(RolePermission::Table, RolePermission::RoleId)
                            .to(Role::Table, Role::Id)
                            .on_delete(ForeignKeyAction::Restrict)
                            .on_update(ForeignKeyAction::Cascade),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk_role_permission_scope")
                            .from(RolePermission::Table, RolePermission::ScopeId)
                            .to(Scope::Table, Scope::Id)
                            .on_delete(ForeignKeyAction::Restrict)
                            .on_update(ForeignKeyAction::Cascade),
                    )
                    .to_owned(),
            )
            .await?;
        manager
            .create_index(
                Index::create()
                    .name("idx_role_permission_scope")
                    .table(RolePermission::Table)
                    .col(RolePermission::ScopeId)
                    .to_owned(),
            )
            .await?;
        manager
            .create_index(
                Index::create()
                    .unique()
                    .name("uq_role_permission_membership")
                    .table(RolePermission::Table)
                    .col(RolePermission::RoleId)
                    .col(RolePermission::ScopeId)
                    .to_owned(),
            )
            .await?;
        Ok(())
    }
    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(Table::drop().table(RolePermission::Table).to_owned())
            .await
    }
}
