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
pub enum Role {
    Table,
    Id,
    Oid,
    Name,
    Description,
    Enabled,
    Version,
    BuiltIn,
    Names,
    Descriptions,
    CreatedAt,
    UpdatedAt,
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
                    .table(Role::Table)
                    .col(pk_auto(Role::Id).big_integer())
                    .col(uuid_uniq(Role::Oid))
                    .col(ColumnDef::new(Role::Name).text().not_null())
                    .col(
                        ColumnDef::new(Role::Description)
                            .text()
                            .not_null()
                            .default(Expr::value("")),
                    )
                    .col(
                        ColumnDef::new(Role::Enabled)
                            .boolean()
                            .not_null()
                            .default(true),
                    )
                    .col(
                        ColumnDef::new(Role::Version)
                            .uuid()
                            .not_null()
                            .default(Func::cust(Alias::new("gen_random_uuid"))),
                    )
                    .col(
                        ColumnDef::new(Role::BuiltIn)
                            .boolean()
                            .not_null()
                            .default(false),
                    )
                    .col(
                        ColumnDef::new(Role::Names)
                            .json_binary()
                            .not_null()
                            .default(empty_json_object()),
                    )
                    .col(
                        ColumnDef::new(Role::Descriptions)
                            .json_binary()
                            .not_null()
                            .default(empty_json_object()),
                    )
                    .col(
                        timestamp_with_time_zone(Role::CreatedAt)
                            .default(Expr::current_timestamp()),
                    )
                    .col(ColumnDef::new(Role::UpdatedAt).timestamp_with_time_zone())
                    .to_owned(),
            )
            .await?;
        manager
            .create_index(
                Index::create()
                    .name("idx_role_created_id")
                    .table(Role::Table)
                    .col((Role::CreatedAt, IndexOrder::Desc))
                    .col((Role::Id, IndexOrder::Desc))
                    .to_owned(),
            )
            .await?;
        Ok(())
    }
    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(Table::drop().table(Role::Table).to_owned())
            .await
    }
}
