use sea_orm_migration::prelude::ConditionalStatement;
use sea_orm_migration::prelude::ExprTrait;
use sea_orm_migration::sea_orm;
use sea_orm_migration::{
    async_trait,
    prelude::{
        Alias, ColumnDef, DbErr, DeriveIden, DeriveMigrationName, Expr, ForeignKey,
        ForeignKeyAction, Func, Index, IndexOrder, MigrationTrait, SchemaManager, Table,
    },
    schema::{pk_auto, timestamp_with_time_zone, uuid_uniq},
};

use crate::{m20260305_071904_create_user::User, m20261022_000005_create_role::Role};

#[derive(DeriveMigrationName)]
pub struct Migration;

#[derive(DeriveIden)]
pub enum UserRole {
    Table,
    Id,
    Oid,
    UserId,
    RoleId,
    GrantedByUserId,
    Reason,
    Enabled,
    RevokedAt,
    Version,
    CreatedAt,
    UpdatedAt,
}

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .create_table(
                Table::create()
                    .table(UserRole::Table)
                    .col(pk_auto(UserRole::Id).big_integer())
                    .col(uuid_uniq(UserRole::Oid))
                    .col(ColumnDef::new(UserRole::UserId).big_integer().not_null())
                    .col(ColumnDef::new(UserRole::RoleId).big_integer().not_null())
                    .col(ColumnDef::new(UserRole::GrantedByUserId).big_integer())
                    .col(ColumnDef::new(UserRole::Reason).text().not_null())
                    .col(
                        ColumnDef::new(UserRole::Enabled)
                            .boolean()
                            .not_null()
                            .default(true),
                    )
                    .col(ColumnDef::new(UserRole::RevokedAt).timestamp_with_time_zone())
                    .col(
                        ColumnDef::new(UserRole::Version)
                            .uuid()
                            .not_null()
                            .default(Func::cust(Alias::new("gen_random_uuid"))),
                    )
                    .col(
                        timestamp_with_time_zone(UserRole::CreatedAt)
                            .default(Expr::current_timestamp()),
                    )
                    .col(ColumnDef::new(UserRole::UpdatedAt).timestamp_with_time_zone())
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk_user_role_user")
                            .from(UserRole::Table, UserRole::UserId)
                            .to(User::Table, User::Id)
                            .on_delete(ForeignKeyAction::Restrict)
                            .on_update(ForeignKeyAction::Cascade),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk_user_role_role")
                            .from(UserRole::Table, UserRole::RoleId)
                            .to(Role::Table, Role::Id)
                            .on_delete(ForeignKeyAction::Restrict)
                            .on_update(ForeignKeyAction::Cascade),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk_user_role_granted_by")
                            .from(UserRole::Table, UserRole::GrantedByUserId)
                            .to(User::Table, User::Id)
                            .on_delete(ForeignKeyAction::Restrict)
                            .on_update(ForeignKeyAction::Cascade),
                    )
                    .to_owned(),
            )
            .await?;
        manager
            .create_index(
                Index::create()
                    .unique()
                    .name("uq_user_role_active_user_role")
                    .table(UserRole::Table)
                    .col(UserRole::UserId)
                    .col(UserRole::RoleId)
                    .and_where(Expr::col(UserRole::Enabled).eq(true))
                    .and_where(Expr::col(UserRole::RevokedAt).is_null())
                    .to_owned(),
            )
            .await?;
        manager
            .create_index(
                Index::create()
                    .name("idx_user_role_user_created")
                    .table(UserRole::Table)
                    .col(UserRole::UserId)
                    .col((UserRole::CreatedAt, IndexOrder::Desc))
                    .col((UserRole::Id, IndexOrder::Desc))
                    .to_owned(),
            )
            .await?;
        manager
            .create_index(
                Index::create()
                    .name("idx_user_role_role_created")
                    .table(UserRole::Table)
                    .col(UserRole::RoleId)
                    .col((UserRole::CreatedAt, IndexOrder::Desc))
                    .col((UserRole::Id, IndexOrder::Desc))
                    .to_owned(),
            )
            .await?;
        Ok(())
    }
    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(Table::drop().table(UserRole::Table).to_owned())
            .await
    }
}
