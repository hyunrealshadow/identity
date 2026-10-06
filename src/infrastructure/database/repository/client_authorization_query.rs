use chrono::{DateTime, Utc};
use sea_orm::{
    sea_query,
    sea_query::{
        CommonTableExpression, Cond, Expr, ExprTrait, Func, Iden, JoinType, LockBehavior, LockType,
        Order, Query, SelectStatement, UnionType, UpdateStatement, WithClause,
    },
};
use serde_json::json;
use uuid::Uuid;

use crate::database::{
    entity::{client, client_authorization},
    query::{json_text, jsonb_set},
};

#[derive(Iden)]
enum AuthorizationQuery {
    Due,
    Ancestors,
    Family,
    Parent,
    Child,
    RootOid,
    Compromised,
}

fn client_id(oid: Uuid) -> SelectStatement {
    Query::select()
        .column(client::Column::Id)
        .from(client::Entity)
        .and_where(Expr::col(client::Column::Oid).eq(oid))
        .to_owned()
}

pub(super) fn expiration_batch() -> UpdateStatement {
    let due = Query::select()
        .column(client_authorization::Column::Id)
        .from(client_authorization::Entity)
        .and_where(Expr::col(client_authorization::Column::IsExpired).eq(false))
        .and_where(
            Expr::col(client_authorization::Column::ExpiresAt).lte(Expr::current_timestamp()),
        )
        .order_by(client_authorization::Column::ExpiresAt, Order::Asc)
        .limit(1000)
        .lock_with_behavior(LockType::Update, LockBehavior::SkipLocked)
        .to_owned();
    Query::update()
        .table(client_authorization::Entity)
        .value(client_authorization::Column::IsExpired, true)
        .value(
            client_authorization::Column::UpdatedAt,
            Expr::current_timestamp(),
        )
        .from(AuthorizationQuery::Due)
        .and_where(
            Expr::col((
                client_authorization::Entity,
                client_authorization::Column::Id,
            ))
            .equals((AuthorizationQuery::Due, client_authorization::Column::Id)),
        )
        .with_cte(
            CommonTableExpression::new()
                .table_name(AuthorizationQuery::Due)
                .query(due)
                .to_owned(),
        )
        .to_owned()
}

pub(super) fn refresh_root(refresh_oid: Uuid, client_oid: Uuid) -> SelectStatement {
    let parent = Query::select()
        .columns([
            (
                AuthorizationQuery::Parent,
                client_authorization::Column::Oid,
            ),
            (
                AuthorizationQuery::Parent,
                client_authorization::Column::Data,
            ),
        ])
        .from_as(client_authorization::Entity, AuthorizationQuery::Parent)
        .join(
            JoinType::InnerJoin,
            AuthorizationQuery::Ancestors,
            Expr::col((
                AuthorizationQuery::Parent,
                client_authorization::Column::Oid,
            ))
            .cast_as("text")
            .eq(json_text(
                (
                    AuthorizationQuery::Ancestors,
                    client_authorization::Column::Data,
                ),
                "rotated_from",
            )),
        )
        .and_where(
            Expr::col((
                AuthorizationQuery::Parent,
                client_authorization::Column::Type,
            ))
            .eq("refresh_token"),
        )
        .to_owned();
    let ancestors = Query::select()
        .columns([
            client_authorization::Column::Oid,
            client_authorization::Column::Data,
        ])
        .from(client_authorization::Entity)
        .and_where(Expr::col(client_authorization::Column::Oid).eq(refresh_oid))
        .and_where(Expr::col(client_authorization::Column::ClientId).eq(client_id(client_oid)))
        .and_where(Expr::col(client_authorization::Column::Type).eq("refresh_token"))
        .union(UnionType::All, parent)
        .to_owned();
    let with = WithClause::new()
        .recursive(true)
        .cte(
            CommonTableExpression::new()
                .table_name(AuthorizationQuery::Ancestors)
                .query(ancestors)
                .to_owned(),
        )
        .to_owned();
    Query::select()
        .expr_as(
            Expr::col(client_authorization::Column::Oid),
            AuthorizationQuery::RootOid,
        )
        .from(AuthorizationQuery::Ancestors)
        .and_where(json_text(client_authorization::Column::Data, "rotated_from").is_null())
        .limit(1)
        .with_cte(with)
        .to_owned()
}

pub(super) fn refresh_compromised(root_oid: Uuid) -> SelectStatement {
    let flag = |field| {
        Expr::expr(Func::coalesce([
            json_text(client_authorization::Column::Data, field),
            Expr::value("false"),
        ]))
        .eq("true")
    };
    Query::select()
        .expr_as(
            flag("replay_detected").or(flag("grant_revoked")),
            AuthorizationQuery::Compromised,
        )
        .from(client_authorization::Entity)
        .and_where(Expr::col(client_authorization::Column::Oid).eq(root_oid))
        .to_owned()
}

pub(super) fn authorization_data(oid: Uuid) -> SelectStatement {
    Query::select()
        .column(client_authorization::Column::Data)
        .from(client_authorization::Entity)
        .and_where(Expr::col(client_authorization::Column::Oid).eq(oid))
        .to_owned()
}

pub(super) fn consume_par(digest: &str, client_oid: Uuid, now: DateTime<Utc>) -> UpdateStatement {
    Query::update()
        .table(client_authorization::Entity)
        .value(client_authorization::Column::CompletedAt, now)
        .value(client_authorization::Column::UpdatedAt, now)
        .and_where(Expr::col(client_authorization::Column::Type).eq("pushed_authorization_request"))
        .and_where(json_text(client_authorization::Column::Data, "request_uri_digest").eq(digest))
        .and_where(Expr::col(client_authorization::Column::ClientId).eq(client_id(client_oid)))
        .and_where(Expr::col(client_authorization::Column::ExpiresAt).gt(now))
        .and_where(Expr::col(client_authorization::Column::CompletedAt).is_null())
        .and_where(Expr::col(client_authorization::Column::RevokedAt).is_null())
        .and_where(Expr::col(client_authorization::Column::IsExpired).eq(false))
        .returning_all()
        .to_owned()
}

pub(super) fn mark_refresh_flag(root_oid: Uuid, flag: &str, now: DateTime<Utc>) -> UpdateStatement {
    Query::update()
        .table(client_authorization::Entity)
        .value(
            client_authorization::Column::Data,
            jsonb_set(
                client_authorization::Column::Data,
                flag,
                Expr::value(json!(true)),
            ),
        )
        .value(client_authorization::Column::UpdatedAt, now)
        .and_where(Expr::col(client_authorization::Column::Oid).eq(root_oid))
        .to_owned()
}

pub(super) fn revoke_refresh_family(
    root_oid: Uuid,
    client_oid: Uuid,
    authorization_code_oid: &str,
    device_authorization_oid: &str,
    now: DateTime<Utc>,
) -> UpdateStatement {
    let children = Query::select()
        .column((AuthorizationQuery::Child, client_authorization::Column::Oid))
        .from_as(client_authorization::Entity, AuthorizationQuery::Child)
        .join(
            JoinType::InnerJoin,
            AuthorizationQuery::Family,
            json_text(
                (
                    AuthorizationQuery::Child,
                    client_authorization::Column::Data,
                ),
                "rotated_from",
            )
            .eq(Expr::col((
                AuthorizationQuery::Family,
                client_authorization::Column::Oid,
            ))
            .cast_as("text")),
        )
        .and_where(
            Expr::col((
                AuthorizationQuery::Child,
                client_authorization::Column::Type,
            ))
            .eq("refresh_token"),
        )
        .to_owned();
    let family = Query::select()
        .column(client_authorization::Column::Oid)
        .from(client_authorization::Entity)
        .and_where(Expr::col(client_authorization::Column::Oid).eq(root_oid))
        .union(UnionType::All, children)
        .to_owned();
    let with = WithClause::new()
        .recursive(true)
        .cte(
            CommonTableExpression::new()
                .table_name(AuthorizationQuery::Family)
                .query(family)
                .to_owned(),
        )
        .to_owned();
    let ids = Query::select()
        .column(client_authorization::Column::Oid)
        .from(AuthorizationQuery::Family)
        .to_owned();
    let text_ids = Query::select()
        .expr(Expr::col(client_authorization::Column::Oid).cast_as("text"))
        .from(AuthorizationQuery::Family)
        .to_owned();
    let mut links = Cond::any().add(
        json_text(client_authorization::Column::Data, "refresh_token_oid").in_subquery(text_ids),
    );
    if !authorization_code_oid.is_empty() {
        links = links.add(
            json_text(client_authorization::Column::Data, "authorization_code_oid")
                .eq(authorization_code_oid),
        );
    }
    if !device_authorization_oid.is_empty() {
        links = links.add(
            json_text(
                client_authorization::Column::Data,
                "device_authorization_oid",
            )
            .eq(device_authorization_oid),
        );
    }
    Query::update()
        .table(client_authorization::Entity)
        .value(client_authorization::Column::RevokedAt, now)
        .value(client_authorization::Column::UpdatedAt, now)
        .and_where(Expr::col(client_authorization::Column::ClientId).eq(client_id(client_oid)))
        .and_where(Expr::col(client_authorization::Column::RevokedAt).is_null())
        .cond_where(
            Cond::any()
                .add(Expr::col(client_authorization::Column::Oid).in_subquery(ids))
                .add(
                    Cond::all()
                        .add(Expr::col(client_authorization::Column::Type).eq("access_token"))
                        .add(links),
                ),
        )
        .with_cte(with)
        .to_owned()
}

pub(super) fn revoke_token_for_client(
    oid: Expr,
    client_oid: Uuid,
    kind: &str,
    now: DateTime<Utc>,
) -> UpdateStatement {
    Query::update()
        .table(client_authorization::Entity)
        .value(client_authorization::Column::RevokedAt, now)
        .value(client_authorization::Column::UpdatedAt, now)
        .and_where(oid)
        .and_where(Expr::col(client_authorization::Column::ClientId).eq(client_id(client_oid)))
        .and_where(Expr::col(client_authorization::Column::Type).eq(kind))
        .and_where(Expr::col(client_authorization::Column::RevokedAt).is_null())
        .to_owned()
}
