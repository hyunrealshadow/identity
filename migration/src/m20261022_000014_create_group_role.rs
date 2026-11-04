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

use crate::{
    m20260305_071904_create_user::User, m20261022_000005_create_role::Role,
    m20261022_000012_create_user_group::UserGroup,
};

#[derive(DeriveMigrationName)]
pub struct Migration;

#[derive(DeriveIden)]
pub enum GroupRole {
    Table,
    Id,
    Oid,
    GroupId,
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
                    .table(GroupRole::Table)
                    .col(pk_auto(GroupRole::Id).big_integer())
                    .col(uuid_uniq(GroupRole::Oid))
                    .col(ColumnDef::new(GroupRole::GroupId).big_integer().not_null())
                    .col(ColumnDef::new(GroupRole::RoleId).big_integer().not_null())
                    .col(ColumnDef::new(GroupRole::GrantedByUserId).big_integer())
                    .col(ColumnDef::new(GroupRole::Reason).text().not_null())
                    .col(
                        ColumnDef::new(GroupRole::Enabled)
                            .boolean()
                            .not_null()
                            .default(true),
                    )
                    .col(ColumnDef::new(GroupRole::RevokedAt).timestamp_with_time_zone())
                    .col(
                        ColumnDef::new(GroupRole::Version)
                            .uuid()
                            .not_null()
                            .default(Func::cust(Alias::new("gen_random_uuid"))),
                    )
                    .col(
                        timestamp_with_time_zone(GroupRole::CreatedAt)
                            .default(Expr::current_timestamp()),
                    )
                    .col(ColumnDef::new(GroupRole::UpdatedAt).timestamp_with_time_zone())
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk_group_role_group")
                            .from(GroupRole::Table, GroupRole::GroupId)
                            .to(UserGroup::Table, UserGroup::Id)
                            .on_delete(ForeignKeyAction::Restrict)
                            .on_update(ForeignKeyAction::Cascade),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk_group_role_role")
                            .from(GroupRole::Table, GroupRole::RoleId)
                            .to(Role::Table, Role::Id)
                            .on_delete(ForeignKeyAction::Restrict)
                            .on_update(ForeignKeyAction::Cascade),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk_group_role_granted_by")
                            .from(GroupRole::Table, GroupRole::GrantedByUserId)
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
                    .name("uq_group_role_active_group_role")
                    .table(GroupRole::Table)
                    .unique()
                    .col(GroupRole::GroupId)
                    .col(GroupRole::RoleId)
                    .and_where(Expr::col(GroupRole::Enabled).eq(true))
                    .and_where(Expr::col(GroupRole::RevokedAt).is_null())
                    .to_owned(),
            )
            .await?;
        manager
            .create_index(
                Index::create()
                    .name("idx_group_role_group_created")
                    .table(GroupRole::Table)
                    .col(GroupRole::GroupId)
                    .col((GroupRole::CreatedAt, IndexOrder::Desc))
                    .col((GroupRole::Id, IndexOrder::Desc))
                    .to_owned(),
            )
            .await?;
        manager
            .create_index(
                Index::create()
                    .name("idx_group_role_role_created")
                    .table(GroupRole::Table)
                    .col(GroupRole::RoleId)
                    .col((GroupRole::CreatedAt, IndexOrder::Desc))
                    .col((GroupRole::Id, IndexOrder::Desc))
                    .to_owned(),
            )
            .await?;
        Ok(())
    }
    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(Table::drop().table(GroupRole::Table).to_owned())
            .await
    }
}
