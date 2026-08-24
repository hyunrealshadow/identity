use crate::m20260305_071904_create_user::User;
use sea_orm_migration::prelude::{
    DbErr, DeriveIden, DeriveMigrationName, Expr, MigrationTrait, SchemaManager, Table,
};
use sea_orm_migration::schema::json_binary;
use sea_orm_migration::{async_trait, sea_orm};

#[derive(DeriveMigrationName)]
pub struct Migration;

#[derive(DeriveIden)]
enum UserPreferences {
    Preferences,
}

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(User::Table)
                    .add_column(
                        json_binary(UserPreferences::Preferences)
                            .default(Expr::cust("'{}'::jsonb")),
                    )
                    .to_owned(),
            )
            .await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(User::Table)
                    .drop_column(UserPreferences::Preferences)
                    .to_owned(),
            )
            .await
    }
}
