use sea_orm_migration::{async_trait, sea_orm};
use sea_orm_migration::{
    prelude::{
        DbErr, DeriveIden, DeriveMigrationName, Expr, Index, MigrationTrait, SchemaManager, Table,
    },
    schema::{
        boolean, pk_auto, string, timestamp_with_time_zone, timestamp_with_time_zone_null,
        uuid_uniq,
    },
};

#[derive(DeriveMigrationName)]
pub struct Migration;

#[derive(DeriveIden)]
pub enum Scope {
    Table,
    Id,
    Oid,
    Protocol,
    Name,
    DisplayName,
    Description,
    BuiltIn,
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
                    .col(uuid_uniq(Scope::Oid).default(Expr::cust("gen_random_uuid()")))
                    .col(string(Scope::Protocol))
                    .col(string(Scope::Name))
                    .col(string(Scope::DisplayName))
                    .col(string(Scope::Description))
                    .col(boolean(Scope::BuiltIn).default(false))
                    .col(
                        timestamp_with_time_zone(Scope::CreatedAt)
                            .default(Expr::current_timestamp()),
                    )
                    .col(timestamp_with_time_zone_null(Scope::UpdatedAt))
                    .to_owned(),
            )
            .await?;

        manager
            .create_index(
                Index::create()
                    .table(Scope::Table)
                    .name("idx_scope_protocol_name")
                    .col(Scope::Protocol)
                    .col(Scope::Name)
                    .unique()
                    .to_owned(),
            )
            .await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_index(
                Index::drop()
                    .table(Scope::Table)
                    .name("idx_scope_protocol_name")
                    .to_owned(),
            )
            .await?;
        manager
            .drop_table(Table::drop().table(Scope::Table).to_owned())
            .await
    }
}
