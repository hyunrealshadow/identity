use sea_orm_migration::prelude::ConditionalStatement;
use sea_orm_migration::sea_orm;
use sea_orm_migration::{
    async_trait,
    prelude::{
        Alias, ColumnDef, DbErr, DeriveIden, DeriveMigrationName, Expr, ExprTrait, ForeignKey,
        ForeignKeyAction, Func, Index, IndexOrder, MigrationTrait, SchemaManager, Table,
    },
    schema::{
        boolean, json_binary, pk_auto, string, timestamp_with_time_zone,
        timestamp_with_time_zone_null, uuid_null, uuid_uniq,
    },
};

use crate::m20261001_000001_create_resource::Resource;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[derive(DeriveIden)]
pub enum Scope {
    Table,
    Id,
    Oid,
    ResourceId,
    Code,
    Name,
    Names,
    Version,
    Description,
    Descriptions,
    BuiltIn,
    Enabled,
    CreatedAt,
    UpdatedAt,
}

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .create_table(
                Table::create()
                    .table(Scope::Table)
                    .if_not_exists()
                    .col(pk_auto(Scope::Id).big_integer())
                    .col(uuid_uniq(Scope::Oid).default(Func::cust(Alias::new("gen_random_uuid"))))
                    .col(uuid_null(Scope::ResourceId))
                    .col(string(Scope::Code))
                    .col(ColumnDef::new(Scope::Name).text().not_null())
                    .col(
                        json_binary(Scope::Names)
                            .default(Expr::val("{}").cast_as(Alias::new("jsonb"))),
                    )
                    .col(
                        ColumnDef::new(Scope::Version)
                            .uuid()
                            .not_null()
                            .default(Func::cust(Alias::new("gen_random_uuid"))),
                    )
                    .col(ColumnDef::new(Scope::Description).text().not_null())
                    .col(
                        json_binary(Scope::Descriptions)
                            .default(Expr::val("{}").cast_as(Alias::new("jsonb"))),
                    )
                    .col(boolean(Scope::BuiltIn).default(false))
                    .col(boolean(Scope::Enabled).default(true))
                    .col(
                        timestamp_with_time_zone(Scope::CreatedAt)
                            .default(Expr::current_timestamp()),
                    )
                    .col(timestamp_with_time_zone_null(Scope::UpdatedAt))
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk_scope_resource")
                            .from(Scope::Table, Scope::ResourceId)
                            .to(Resource::Table, Resource::Oid)
                            .on_delete(ForeignKeyAction::Restrict)
                            .on_update(ForeignKeyAction::Cascade),
                    )
                    .to_owned(),
            )
            .await?;

        manager
            .create_index(
                Index::create()
                    .table(Scope::Table)
                    .name("uq_scope_resource_code")
                    .col(Scope::ResourceId)
                    .col(Scope::Code)
                    .unique()
                    .to_owned(),
            )
            .await?;

        manager
            .create_index(
                Index::create()
                    .table(Scope::Table)
                    .name("uq_scope_protocol_code")
                    .col(Scope::Code)
                    .unique()
                    .and_where(Expr::col(Scope::ResourceId).is_null())
                    .to_owned(),
            )
            .await?;

        manager
            .create_index(
                Index::create()
                    .name("idx_scope_created_id")
                    .table(Scope::Table)
                    .col((Scope::CreatedAt, IndexOrder::Desc))
                    .col((Scope::Id, IndexOrder::Desc))
                    .to_owned(),
            )
            .await?;
        manager
            .create_index(
                Index::create()
                    .name("idx_scope_builtin")
                    .table(Scope::Table)
                    .col(Scope::BuiltIn)
                    .to_owned(),
            )
            .await?;
        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(Table::drop().table(Scope::Table).to_owned())
            .await
    }
}
