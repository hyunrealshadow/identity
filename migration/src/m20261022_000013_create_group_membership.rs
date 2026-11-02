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

use crate::{m20260305_071904_create_user::User, m20261022_000012_create_user_group::UserGroup};

#[derive(DeriveMigrationName)]
pub struct Migration;

#[derive(DeriveIden)]
pub enum GroupMembership {
    Table,
    Id,
    Oid,
    GroupId,
    UserId,
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
                    .table(GroupMembership::Table)
                    .col(pk_auto(GroupMembership::Id).big_integer())
                    .col(uuid_uniq(GroupMembership::Oid))
                    .col(
                        ColumnDef::new(GroupMembership::GroupId)
                            .big_integer()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(GroupMembership::UserId)
                            .big_integer()
                            .not_null(),
                    )
                    .col(ColumnDef::new(GroupMembership::GrantedByUserId).big_integer())
                    .col(ColumnDef::new(GroupMembership::Reason).text().not_null())
                    .col(
                        ColumnDef::new(GroupMembership::Enabled)
                            .boolean()
                            .not_null()
                            .default(true),
                    )
                    .col(ColumnDef::new(GroupMembership::RevokedAt).timestamp_with_time_zone())
                    .col(
                        ColumnDef::new(GroupMembership::Version)
                            .uuid()
                            .not_null()
                            .default(Func::cust(Alias::new("gen_random_uuid"))),
                    )
                    .col(
                        timestamp_with_time_zone(GroupMembership::CreatedAt)
                            .default(Expr::current_timestamp()),
                    )
                    .col(ColumnDef::new(GroupMembership::UpdatedAt).timestamp_with_time_zone())
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk_group_membership_group")
                            .from(GroupMembership::Table, GroupMembership::GroupId)
                            .to(UserGroup::Table, UserGroup::Id)
                            .on_delete(ForeignKeyAction::Restrict)
                            .on_update(ForeignKeyAction::Cascade),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk_group_membership_user")
                            .from(GroupMembership::Table, GroupMembership::UserId)
                            .to(User::Table, User::Id)
                            .on_delete(ForeignKeyAction::Restrict)
                            .on_update(ForeignKeyAction::Cascade),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk_group_membership_granted_by")
                            .from(GroupMembership::Table, GroupMembership::GrantedByUserId)
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
                    .name("uq_group_membership_active_group_user")
                    .table(GroupMembership::Table)
                    .unique()
                    .col(GroupMembership::GroupId)
                    .col(GroupMembership::UserId)
                    .and_where(Expr::col(GroupMembership::Enabled).eq(true))
                    .and_where(Expr::col(GroupMembership::RevokedAt).is_null())
                    .to_owned(),
            )
            .await?;
        manager
            .create_index(
                Index::create()
                    .name("idx_group_membership_user_created")
                    .table(GroupMembership::Table)
                    .col(GroupMembership::UserId)
                    .col((GroupMembership::CreatedAt, IndexOrder::Desc))
                    .col((GroupMembership::Id, IndexOrder::Desc))
                    .to_owned(),
            )
            .await?;
        manager
            .create_index(
                Index::create()
                    .name("idx_group_membership_group_created")
                    .table(GroupMembership::Table)
                    .col(GroupMembership::GroupId)
                    .col((GroupMembership::CreatedAt, IndexOrder::Desc))
                    .col((GroupMembership::Id, IndexOrder::Desc))
                    .to_owned(),
            )
            .await?;
        Ok(())
    }
    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(Table::drop().table(GroupMembership::Table).to_owned())
            .await
    }
}
