use sea_orm_migration::{
    prelude::*,
    schema::{
        json_binary_null, pk_auto, text, text_null, timestamp_with_time_zone, uuid_null, uuid_uniq,
    },
    sea_orm::sea_query::Check,
};

#[derive(DeriveMigrationName)]
pub struct Migration;

/// Append-only security audit journal. Enumerated columns hold the stable
/// values of the Rust audit enums; the application validates them on write
/// and read.
#[derive(DeriveIden)]
pub(crate) enum Audit {
    Table,
    Id,
    Oid,
    OccurredAt,
    Category,
    Action,
    Outcome,
    FailureReason,
    ActorKind,
    ActorOid,
    ActorLabel,
    TargetKind,
    TargetOid,
    TargetLabel,
    ClientOid,
    AuthMethods,
    IpAddress,
    UserAgent,
    RequestId,
    TraceId,
    Changes,
}

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .create_table(
                Table::create()
                    .table(Audit::Table)
                    .col(pk_auto(Audit::Id).big_integer())
                    .col(uuid_uniq(Audit::Oid).default(Func::cust(Alias::new("gen_random_uuid"))))
                    .col(
                        timestamp_with_time_zone(Audit::OccurredAt)
                            .default(Func::cust(Alias::new("clock_timestamp"))),
                    )
                    .col(text(Audit::Category))
                    .col(text(Audit::Action))
                    .col(text(Audit::Outcome))
                    .col(text_null(Audit::FailureReason))
                    .col(text(Audit::ActorKind))
                    .col(uuid_null(Audit::ActorOid))
                    .col(text_null(Audit::ActorLabel))
                    .col(text_null(Audit::TargetKind))
                    .col(uuid_null(Audit::TargetOid))
                    .col(text_null(Audit::TargetLabel))
                    .col(uuid_null(Audit::ClientOid))
                    .col(json_binary_null(Audit::AuthMethods))
                    .col(text_null(Audit::IpAddress))
                    .col(text_null(Audit::UserAgent))
                    .col(text_null(Audit::RequestId))
                    .col(text_null(Audit::TraceId))
                    .col(json_binary_null(Audit::Changes))
                    .check(Check::named(
                        "audit_failure_reason_matches_outcome",
                        Expr::col(Audit::FailureReason)
                            .is_null()
                            .eq(Expr::col(Audit::Outcome).eq("success")),
                    ))
                    .check(Check::named(
                        "audit_target_is_complete",
                        Expr::col(Audit::TargetKind)
                            .is_null()
                            .eq(Expr::col(Audit::TargetOid).is_null()),
                    ))
                    .to_owned(),
            )
            .await?;

        let indexes = [
            Index::create()
                .name("audit_occurred_at")
                .table(Audit::Table)
                .col(Audit::OccurredAt)
                .col(Audit::Id)
                .to_owned(),
            Index::create()
                .name("audit_category_occurred_at")
                .table(Audit::Table)
                .col(Audit::Category)
                .col(Audit::OccurredAt)
                .col(Audit::Id)
                .to_owned(),
            Index::create()
                .name("audit_action_occurred_at")
                .table(Audit::Table)
                .col(Audit::Action)
                .col(Audit::OccurredAt)
                .col(Audit::Id)
                .to_owned(),
            Index::create()
                .name("audit_actor_occurred_at")
                .table(Audit::Table)
                .col(Audit::ActorOid)
                .col(Audit::OccurredAt)
                .col(Audit::Id)
                .and_where(Expr::col(Audit::ActorOid).is_not_null())
                .to_owned(),
            Index::create()
                .name("audit_target_occurred_at")
                .table(Audit::Table)
                .col(Audit::TargetOid)
                .col(Audit::OccurredAt)
                .col(Audit::Id)
                .and_where(Expr::col(Audit::TargetOid).is_not_null())
                .to_owned(),
            Index::create()
                .name("audit_failure_occurred_at")
                .table(Audit::Table)
                .col(Audit::OccurredAt)
                .col(Audit::Id)
                .and_where(Expr::col(Audit::Outcome).eq("failure"))
                .to_owned(),
            Index::create()
                .name("audit_request_id")
                .table(Audit::Table)
                .col(Audit::RequestId)
                .and_where(Expr::col(Audit::RequestId).is_not_null())
                .to_owned(),
        ];
        for index in indexes {
            manager.create_index(index).await?;
        }
        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(Table::drop().table(Audit::Table).if_exists().to_owned())
            .await
    }
}
