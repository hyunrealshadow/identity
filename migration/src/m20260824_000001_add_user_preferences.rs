use sea_orm_migration::{
    async_trait,
    prelude::{DbErr, DeriveIden, DeriveMigrationName, Expr, MigrationTrait, SchemaManager, Table},
    schema::json_binary,
    sea_orm,
};

use crate::m20260305_071904_create_user::User;

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
