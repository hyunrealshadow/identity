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
pub enum GroupRoleBinding {
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
                    .table(GroupRoleBinding::Table)
                    .col(pk_auto(GroupRoleBinding::Id).big_integer())
                    .col(uuid_uniq(GroupRoleBinding::Oid))
                    .col(
                        ColumnDef::new(GroupRoleBinding::GroupId)
                            .big_integer()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(GroupRoleBinding::RoleId)
                            .big_integer()
                            .not_null(),
                    )
                    .col(ColumnDef::new(GroupRoleBinding::GrantedByUserId).big_integer())
                    .col(ColumnDef::new(GroupRoleBinding::Reason).text().not_null())
                    .col(
                        ColumnDef::new(GroupRoleBinding::Enabled)
                            .boolean()
                            .not_null()
                            .default(true),
                    )
                    .col(ColumnDef::new(GroupRoleBinding::RevokedAt).timestamp_with_time_zone())
                    .col(
                        ColumnDef::new(GroupRoleBinding::Version)
                            .uuid()
                            .not_null()
                            .default(Func::cust(Alias::new("gen_random_uuid"))),
                    )
                    .col(
                        timestamp_with_time_zone(GroupRoleBinding::CreatedAt)
                            .default(Expr::current_timestamp()),
                    )
                    .col(ColumnDef::new(GroupRoleBinding::UpdatedAt).timestamp_with_time_zone())
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk_group_role_binding_group")
                            .from(GroupRoleBinding::Table, GroupRoleBinding::GroupId)
                            .to(UserGroup::Table, UserGroup::Id)
                            .on_delete(ForeignKeyAction::Restrict)
                            .on_update(ForeignKeyAction::Cascade),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk_group_role_binding_role")
                            .from(GroupRoleBinding::Table, GroupRoleBinding::RoleId)
                            .to(Role::Table, Role::Id)
                            .on_delete(ForeignKeyAction::Restrict)
                            .on_update(ForeignKeyAction::Cascade),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk_group_role_binding_granted_by")
                            .from(GroupRoleBinding::Table, GroupRoleBinding::GrantedByUserId)
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
                    .name("uq_group_role_binding_active_group_role")
                    .table(GroupRoleBinding::Table)
                    .unique()
                    .col(GroupRoleBinding::GroupId)
                    .col(GroupRoleBinding::RoleId)
                    .and_where(Expr::col(GroupRoleBinding::Enabled).eq(true))
                    .and_where(Expr::col(GroupRoleBinding::RevokedAt).is_null())
                    .to_owned(),
            )
            .await?;
        manager
            .create_index(
                Index::create()
                    .name("idx_group_role_binding_group_created")
                    .table(GroupRoleBinding::Table)
                    .col(GroupRoleBinding::GroupId)
                    .col((GroupRoleBinding::CreatedAt, IndexOrder::Desc))
                    .col((GroupRoleBinding::Id, IndexOrder::Desc))
                    .to_owned(),
            )
            .await?;
        manager
            .create_index(
                Index::create()
                    .name("idx_group_role_binding_role_created")
                    .table(GroupRoleBinding::Table)
                    .col(GroupRoleBinding::RoleId)
                    .col((GroupRoleBinding::CreatedAt, IndexOrder::Desc))
                    .col((GroupRoleBinding::Id, IndexOrder::Desc))
                    .to_owned(),
            )
            .await?;
        Ok(())
    }
    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(Table::drop().table(GroupRoleBinding::Table).to_owned())
            .await
    }
}
