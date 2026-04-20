use sea_orm_migration::{prelude::*, schema::*};

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
                    .col(uuid_uniq(Client::Oid).default(Expr::cust("gen_random_uuid()")))
                    .col(string(Client::Protocol))
                    .col(string(Client::Name))
                    .col(json_binary_null(Client::Names))
                    .col(string_null(Client::Description))
                    .col(
                        timestamp(Client::CreatedAt)
                            .not_null()
                            .default(Expr::current_timestamp()),
                    )
                    .col(timestamp_null(Client::UpdatedAt))
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
