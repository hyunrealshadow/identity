use crate::m20260306_090746_create_session::Session;
use sea_orm_migration::async_trait;
use sea_orm_migration::prelude::{
    DbErr, DeriveMigrationName, Index, MigrationTrait, SchemaManager,
};

#[derive(DeriveMigrationName)]
pub struct Migration;

const INDEX_NAME: &str = "idx_session_user_relay_order";

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .create_index(
                Index::create()
                    .name(INDEX_NAME)
                    .table(Session::Table)
                    .col(Session::UserId)
                    .col(Session::LastActiveAt)
                    .col(Session::Id)
                    .to_owned(),
            )
            .await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_index(
                Index::drop()
                    .name(INDEX_NAME)
                    .table(Session::Table)
                    .to_owned(),
            )
            .await
    }
}
