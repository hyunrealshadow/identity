use sea_orm_migration::prelude::ExprTrait;
use sea_orm_migration::sea_orm;
use sea_orm_migration::{
    async_trait,
    prelude::{
        Alias, ColumnDef, DbErr, DeriveIden, DeriveMigrationName, Expr, Func, Index, IndexOrder,
        MigrationTrait, SchemaManager, Table,
    },
    schema::{pk_auto, timestamp_with_time_zone, uuid_uniq},
};

#[derive(DeriveMigrationName)]
pub struct Migration;

#[derive(DeriveIden)]
pub enum UserGroup {
    Table,
    Id,
    Oid,
    BuiltIn,
    Name,
    Description,
    Names,
    Descriptions,
    Enabled,
    Version,
    CreatedAt,
    UpdatedAt,
    DeletedAt,
}

fn empty_json_object() -> Expr {
    Expr::val("{}").cast_as(Alias::new("jsonb"))
}

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .create_table(
                Table::create()
                    .table(UserGroup::Table)
                    .col(pk_auto(UserGroup::Id).big_integer())
                    .col(uuid_uniq(UserGroup::Oid))
                    .col(ColumnDef::new(UserGroup::Name).string_len(256).not_null())
                    .col(
                        ColumnDef::new(UserGroup::Description)
                            .text()
                            .not_null()
                            .default(""),
                    )
                    .col(
                        ColumnDef::new(UserGroup::BuiltIn)
                            .boolean()
                            .not_null()
                            .default(false),
                    )
                    .col(
                        ColumnDef::new(UserGroup::Names)
                            .json_binary()
                            .not_null()
                            .default(empty_json_object()),
                    )
                    .col(
                        ColumnDef::new(UserGroup::Descriptions)
                            .json_binary()
                            .not_null()
                            .default(empty_json_object()),
                    )
                    .col(
                        ColumnDef::new(UserGroup::Enabled)
                            .boolean()
                            .not_null()
                            .default(true),
                    )
                    .col(
                        ColumnDef::new(UserGroup::Version)
                            .uuid()
                            .not_null()
                            .default(Func::cust(Alias::new("gen_random_uuid"))),
                    )
                    .col(
                        timestamp_with_time_zone(UserGroup::CreatedAt)
                            .default(Expr::current_timestamp()),
                    )
                    .col(ColumnDef::new(UserGroup::UpdatedAt).timestamp_with_time_zone())
                    .col(ColumnDef::new(UserGroup::DeletedAt).timestamp_with_time_zone())
                    .to_owned(),
            )
            .await?;
        manager
            .create_index(
                Index::create()
                    .name("idx_user_group_created_id")
                    .table(UserGroup::Table)
                    .col((UserGroup::CreatedAt, IndexOrder::Desc))
                    .col((UserGroup::Id, IndexOrder::Desc))
                    .to_owned(),
            )
            .await?;
        Ok(())
    }
    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(Table::drop().table(UserGroup::Table).to_owned())
            .await
    }
}
