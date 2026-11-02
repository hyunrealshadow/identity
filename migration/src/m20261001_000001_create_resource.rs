use sea_orm_migration::sea_orm;
use sea_orm_migration::{
    async_trait,
    prelude::{
        Alias, DbErr, DeriveIden, DeriveMigrationName, Expr, Func, Index, IndexOrder,
        MigrationTrait, SchemaManager, Table,
    },
    schema::{
        boolean, text, text_uniq, timestamp_with_time_zone, timestamp_with_time_zone_null, uuid,
    },
};

#[derive(DeriveMigrationName)]
pub struct Migration;

#[derive(DeriveIden)]
pub enum Resource {
    Table,
    Oid,
    Uri,
    Name,
    Enabled,
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
                    .table(Resource::Table)
                    .if_not_exists()
                    .col(
                        uuid(Resource::Oid)
                            .primary_key()
                            .default(Func::cust(Alias::new("gen_random_uuid"))),
                    )
                    .col(text_uniq(Resource::Uri))
                    .col(text(Resource::Name))
                    .col(boolean(Resource::Enabled).default(true))
                    .col(
                        uuid(Resource::Version)
                            .not_null()
                            .default(Func::cust(Alias::new("gen_random_uuid"))),
                    )
                    .col(
                        timestamp_with_time_zone(Resource::CreatedAt)
                            .default(Expr::current_timestamp()),
                    )
                    .col(timestamp_with_time_zone_null(Resource::UpdatedAt))
                    .to_owned(),
            )
            .await?;
        manager
            .create_index(
                Index::create()
                    .name("idx_resource_created_oid")
                    .table(Resource::Table)
                    .col((Resource::CreatedAt, IndexOrder::Desc))
                    .col((Resource::Oid, IndexOrder::Desc))
                    .to_owned(),
            )
            .await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_index(
                Index::drop()
                    .name("idx_resource_created_oid")
                    .table(Resource::Table)
                    .to_owned(),
            )
            .await?;
        manager
            .drop_table(Table::drop().table(Resource::Table).to_owned())
            .await
    }
}
