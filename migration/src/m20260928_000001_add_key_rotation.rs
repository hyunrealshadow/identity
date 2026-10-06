use crate::m20260319_121151_create_key::Key;

use sea_orm_migration::{async_trait, prelude::*};

#[derive(DeriveMigrationName)]
pub struct Migration;

#[derive(DeriveIden)]
enum RotationColumn {
    RotatedFromOid,
    RotatedAt,
}

const ROTATED_FROM_INDEX_NAME: &str = "key_rotated_from_oid_unique";

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(Key::Table)
                    .add_column(ColumnDef::new(RotationColumn::RotatedFromOid).uuid().null())
                    .add_column(
                        ColumnDef::new(RotationColumn::RotatedAt)
                            .timestamp_with_time_zone()
                            .null(),
                    )
                    .to_owned(),
            )
            .await?;
        manager
            .create_index(
                Index::create()
                    .name(ROTATED_FROM_INDEX_NAME)
                    .table(Key::Table)
                    .col(RotationColumn::RotatedFromOid)
                    .unique()
                    .to_owned(),
            )
            .await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_index(
                Index::drop()
                    .name(ROTATED_FROM_INDEX_NAME)
                    .table(Key::Table)
                    .to_owned(),
            )
            .await?;
        manager
            .alter_table(
                Table::alter()
                    .table(Key::Table)
                    .drop_column(RotationColumn::RotatedAt)
                    .drop_column(RotationColumn::RotatedFromOid)
                    .to_owned(),
            )
            .await
    }
}
