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
pub enum UserRoleBinding {
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
                    .table(UserRoleBinding::Table)
                    .col(pk_auto(UserRoleBinding::Id).big_integer())
                    .col(uuid_uniq(UserRoleBinding::Oid))
                    .col(
                        ColumnDef::new(UserRoleBinding::UserId)
                            .big_integer()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(UserRoleBinding::RoleId)
                            .big_integer()
                            .not_null(),
                    )
                    .col(ColumnDef::new(UserRoleBinding::GrantedByUserId).big_integer())
                    .col(ColumnDef::new(UserRoleBinding::Reason).text().not_null())
                    .col(
                        ColumnDef::new(UserRoleBinding::Enabled)
                            .boolean()
                            .not_null()
                            .default(true),
                    )
                    .col(ColumnDef::new(UserRoleBinding::RevokedAt).timestamp_with_time_zone())
                    .col(
                        ColumnDef::new(UserRoleBinding::Version)
                            .uuid()
                            .not_null()
                            .default(Func::cust(Alias::new("gen_random_uuid"))),
                    )
                    .col(
                        timestamp_with_time_zone(UserRoleBinding::CreatedAt)
                            .default(Expr::current_timestamp()),
                    )
                    .col(ColumnDef::new(UserRoleBinding::UpdatedAt).timestamp_with_time_zone())
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk_user_role_binding_user")
                            .from(UserRoleBinding::Table, UserRoleBinding::UserId)
                            .to(User::Table, User::Id)
                            .on_delete(ForeignKeyAction::Restrict)
                            .on_update(ForeignKeyAction::Cascade),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk_user_role_binding_role")
                            .from(UserRoleBinding::Table, UserRoleBinding::RoleId)
                            .to(Role::Table, Role::Id)
                            .on_delete(ForeignKeyAction::Restrict)
                            .on_update(ForeignKeyAction::Cascade),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk_user_role_binding_granted_by")
                            .from(UserRoleBinding::Table, UserRoleBinding::GrantedByUserId)
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
                    .name("uq_user_role_binding_active_user_role")
                    .table(UserRoleBinding::Table)
                    .col(UserRoleBinding::UserId)
                    .col(UserRoleBinding::RoleId)
                    .and_where(Expr::col(UserRoleBinding::Enabled).eq(true))
                    .and_where(Expr::col(UserRoleBinding::RevokedAt).is_null())
                    .to_owned(),
            )
            .await?;
        manager
            .create_index(
                Index::create()
                    .name("idx_user_role_binding_user_created")
                    .table(UserRoleBinding::Table)
                    .col(UserRoleBinding::UserId)
                    .col((UserRoleBinding::CreatedAt, IndexOrder::Desc))
                    .col((UserRoleBinding::Id, IndexOrder::Desc))
                    .to_owned(),
            )
            .await?;
        manager
            .create_index(
                Index::create()
                    .name("idx_user_role_binding_role_created")
                    .table(UserRoleBinding::Table)
                    .col(UserRoleBinding::RoleId)
                    .col((UserRoleBinding::CreatedAt, IndexOrder::Desc))
                    .col((UserRoleBinding::Id, IndexOrder::Desc))
                    .to_owned(),
            )
            .await?;
        Ok(())
    }
    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(Table::drop().table(UserRoleBinding::Table).to_owned())
            .await
    }
}
