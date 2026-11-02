use sea_orm_migration::prelude::{Alias, ColumnDef, Func};
use sea_orm_migration::{
    async_trait,
    prelude::{DbErr, DeriveIden, DeriveMigrationName, Expr, MigrationTrait, SchemaManager, Table},
    schema::{
        boolean, json_binary_null, pk_auto, string, string_null, timestamp_with_time_zone,
        timestamp_with_time_zone_null, uuid_uniq,
    },
    sea_orm,
};

#[derive(DeriveMigrationName)]
pub struct Migration;

#[derive(DeriveIden)]
pub enum Client {
    Table,
    Id,
    Oid,
    Protocol,
    Name,
    Names,
    Description,
    Descriptions,
    BuiltIn,
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
                    .table(Client::Table)
                    .if_not_exists()
                    .col(pk_auto(Client::Id).big_integer())
                    .col(uuid_uniq(Client::Oid).default(Func::cust(Alias::new("gen_random_uuid"))))
                    .col(string(Client::Protocol))
                    .col(string(Client::Name))
                    .col(json_binary_null(Client::Names))
                    .col(string_null(Client::Description))
                    .col(json_binary_null(Client::Descriptions))
                    .col(boolean(Client::BuiltIn).default(false))
                    .col(
                        ColumnDef::new(Client::Version)
                            .uuid()
                            .not_null()
                            .default(Func::cust(Alias::new("gen_random_uuid"))),
                    )
                    .col(
                        timestamp_with_time_zone(Client::CreatedAt)
                            .not_null()
                            .default(Expr::current_timestamp()),
                    )
                    .col(timestamp_with_time_zone_null(Client::UpdatedAt))
                    .to_owned(),
            )
            .await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(Table::drop().table(Client::Table).to_owned())
            .await
    }
}
