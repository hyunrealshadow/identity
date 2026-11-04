//! Read and page queries for groups, memberships and group roles.

use identity_application::rbac::{
    GroupEntityKind, GroupFilter, GroupManagementRepositoryError, GroupMembershipPageEntry,
    GroupMembershipQuery, GroupMembershipRecord, GroupOrder, GroupPageData, GroupPageEntry,
    GroupQuery, GroupRecord, GroupRoleBindingRecord, GroupRoleOrder, GroupRolePageEntry,
    GroupRoleQuery,
    cursor::{RbacPageDirection, RbacSortKey, RbacTie},
};
use identity_domain::{
    rbac::{GroupMembershipOid, GroupOid, GroupRoleBindingOid, RoleOid},
    user::UserOid,
};
use sea_orm::{ConnectionTrait, DatabaseTransaction, DbBackend, Statement};
use uuid::Uuid;

use super::{
    GroupManagementRepositoryImpl,
    support::{
        Binds, CursorComparison, corrupt, escape_like, keyset_condition, not_found,
        order_is_descending, page_flags, parse_localized, storage, utc,
    },
};

pub(crate) const GROUP_SELECT: &str = "SELECT ug.id, ug.oid, ug.built_in, ug.name, ug.description, ug.names, ug.descriptions, \
            ug.enabled, ug.version, ug.created_at, ug.updated_at FROM user_group ug";

pub(crate) const MEMBERSHIP_SELECT: &str = "SELECT gm.id, gm.oid, g.oid AS group_oid, u.oid AS user_oid, \
            gm.granted_by_user_id, gbu.oid AS granted_by_user_oid, gm.reason, gm.enabled, \
            gm.revoked_at, gm.version, gm.created_at, gm.updated_at \
     FROM group_membership gm \
     JOIN user_group g ON g.id = gm.group_id \
     JOIN \"user\" u ON u.id = gm.user_id \
     LEFT JOIN \"user\" gbu ON gbu.id = gm.granted_by_user_id";

pub(crate) const GROUP_ROLE_SELECT: &str = "SELECT grb.id, grb.oid, g.oid AS group_oid, r.oid AS role_oid, \
            grb.granted_by_user_id, gbu.oid AS granted_by_user_oid, grb.reason, grb.enabled, \
            grb.revoked_at, grb.version, grb.created_at, grb.updated_at, \
            r.name AS role_name \
     FROM group_role grb \
     JOIN user_group g ON g.id = grb.group_id \
     JOIN \"role\" r ON r.id = grb.role_id \
     LEFT JOIN \"user\" gbu ON gbu.id = grb.granted_by_user_id";

pub(crate) fn group_from_row(
    row: &sea_orm::QueryResult,
) -> Result<GroupRecord, GroupManagementRepositoryError> {
    let names = row
        .try_get::<serde_json::Value>("", "names")
        .map_err(storage)?;
    let descriptions = row
        .try_get::<serde_json::Value>("", "descriptions")
        .map_err(storage)?;
    Ok(GroupRecord {
        oid: GroupOid(row.try_get::<Uuid>("", "oid").map_err(storage)?),
        built_in: row.try_get::<bool>("", "built_in").map_err(storage)?,
        name: row.try_get::<String>("", "name").map_err(storage)?,
        description: row.try_get::<String>("", "description").map_err(storage)?,
        names: parse_localized(names)?,
        descriptions: parse_localized(descriptions)?,
        enabled: row.try_get::<bool>("", "enabled").map_err(storage)?,
        version: row.try_get::<Uuid>("", "version").map_err(storage)?,
        created_at: utc(row
            .try_get::<chrono::DateTime<chrono::FixedOffset>>("", "created_at")
            .map_err(storage)?),
        updated_at: row
            .try_get::<Option<chrono::DateTime<chrono::FixedOffset>>>("", "updated_at")
            .map_err(storage)?
            .map(utc),
    })
}

pub(crate) fn membership_from_row(
    row: &sea_orm::QueryResult,
) -> Result<GroupMembershipRecord, GroupManagementRepositoryError> {
    Ok(GroupMembershipRecord {
        oid: GroupMembershipOid(row.try_get::<Uuid>("", "oid").map_err(storage)?),
        group_oid: GroupOid(row.try_get::<Uuid>("", "group_oid").map_err(storage)?),
        user_oid: UserOid(row.try_get::<Uuid>("", "user_oid").map_err(storage)?),
        granted_by_user_oid: row
            .try_get::<Option<Uuid>>("", "granted_by_user_oid")
            .map_err(storage)?
            .map(UserOid),
        reason: row.try_get::<String>("", "reason").map_err(storage)?,
        enabled: row.try_get::<bool>("", "enabled").map_err(storage)?,
        revoked_at: row
            .try_get::<Option<chrono::DateTime<chrono::FixedOffset>>>("", "revoked_at")
            .map_err(storage)?
            .map(utc),
        version: row.try_get::<Uuid>("", "version").map_err(storage)?,
        created_at: utc(row
            .try_get::<chrono::DateTime<chrono::FixedOffset>>("", "created_at")
            .map_err(storage)?),
        updated_at: row
            .try_get::<Option<chrono::DateTime<chrono::FixedOffset>>>("", "updated_at")
            .map_err(storage)?
            .map(utc),
    })
}

pub(crate) fn group_role_from_row(
    row: &sea_orm::QueryResult,
) -> Result<(GroupRoleBindingRecord, String), GroupManagementRepositoryError> {
    let record = GroupRoleBindingRecord {
        oid: GroupRoleBindingOid(row.try_get::<Uuid>("", "oid").map_err(storage)?),
        group_oid: GroupOid(row.try_get::<Uuid>("", "group_oid").map_err(storage)?),
        role_oid: RoleOid(row.try_get::<Uuid>("", "role_oid").map_err(storage)?),
        granted_by_user_oid: row
            .try_get::<Option<Uuid>>("", "granted_by_user_oid")
            .map_err(storage)?
            .map(UserOid),
        reason: row.try_get::<String>("", "reason").map_err(storage)?,
        enabled: row.try_get::<bool>("", "enabled").map_err(storage)?,
        revoked_at: row
            .try_get::<Option<chrono::DateTime<chrono::FixedOffset>>>("", "revoked_at")
            .map_err(storage)?
            .map(utc),
        version: row.try_get::<Uuid>("", "version").map_err(storage)?,
        created_at: utc(row
            .try_get::<chrono::DateTime<chrono::FixedOffset>>("", "created_at")
            .map_err(storage)?),
        updated_at: row
            .try_get::<Option<chrono::DateTime<chrono::FixedOffset>>>("", "updated_at")
            .map_err(storage)?
            .map(utc),
    };
    let role_name = row.try_get::<String>("", "role_name").map_err(storage)?;
    Ok((record, role_name))
}

pub(crate) async fn load_group_by_oid<C: ConnectionTrait>(
    db: &C,
    oid: GroupOid,
) -> Result<Option<GroupRecord>, GroupManagementRepositoryError> {
    let row = db
        .query_one_raw(Statement::from_sql_and_values(
            DbBackend::Postgres,
            format!("{GROUP_SELECT} WHERE ug.oid = $1 AND ug.deleted_at IS NULL"),
            [Uuid::from(oid).into()],
        ))
        .await
        .map_err(storage)?;
    row.as_ref().map(group_from_row).transpose()
}

pub(crate) async fn load_membership_by_oid<C: ConnectionTrait>(
    db: &C,
    oid: GroupMembershipOid,
) -> Result<GroupMembershipRecord, GroupManagementRepositoryError> {
    let row = db
        .query_one_raw(Statement::from_sql_and_values(
            DbBackend::Postgres,
            format!("{MEMBERSHIP_SELECT} WHERE gm.oid = $1 AND g.deleted_at IS NULL"),
            [Uuid::from(oid).into()],
        ))
        .await
        .map_err(storage)?
        .ok_or_else(|| not_found(GroupEntityKind::Membership))?;
    membership_from_row(&row)
}

pub(crate) async fn find_membership_by_oid<C: ConnectionTrait>(
    db: &C,
    oid: GroupMembershipOid,
) -> Result<Option<GroupMembershipRecord>, GroupManagementRepositoryError> {
    let row = db
        .query_one_raw(Statement::from_sql_and_values(
            DbBackend::Postgres,
            format!("{MEMBERSHIP_SELECT} WHERE gm.oid = $1 AND g.deleted_at IS NULL"),
            [Uuid::from(oid).into()],
        ))
        .await
        .map_err(storage)?;
    row.as_ref().map(membership_from_row).transpose()
}

pub(crate) async fn find_group_role_by_oid<C: ConnectionTrait>(
    db: &C,
    oid: GroupRoleBindingOid,
) -> Result<Option<GroupRoleBindingRecord>, GroupManagementRepositoryError> {
    let row = db
        .query_one_raw(Statement::from_sql_and_values(
            DbBackend::Postgres,
            format!("{GROUP_ROLE_SELECT} WHERE grb.oid = $1 AND g.deleted_at IS NULL"),
            [Uuid::from(oid).into()],
        ))
        .await
        .map_err(storage)?;
    row.as_ref()
        .map(group_role_from_row)
        .transpose()
        .map(|value| value.map(|(record, _)| record))
}

pub(crate) async fn load_group_by_id_locked(
    txn: &DatabaseTransaction,
    id: i64,
) -> Result<GroupRecord, GroupManagementRepositoryError> {
    let row = txn
        .query_one_raw(Statement::from_sql_and_values(
            DbBackend::Postgres,
            format!("{GROUP_SELECT} WHERE ug.id = $1 AND ug.deleted_at IS NULL FOR UPDATE OF ug"),
            [id.into()],
        ))
        .await
        .map_err(storage)?
        .ok_or_else(|| not_found(GroupEntityKind::Group))?;
    group_from_row(&row)
}

pub(crate) async fn group_id_by_oid_locked<C: ConnectionTrait>(
    db: &C,
    oid: GroupOid,
) -> Result<i64, GroupManagementRepositoryError> {
    let row = db
        .query_one_raw(Statement::from_sql_and_values(
            DbBackend::Postgres,
            "SELECT id FROM user_group \
             WHERE oid = $1 AND deleted_at IS NULL FOR UPDATE",
            [Uuid::from(oid).into()],
        ))
        .await
        .map_err(storage)?;
    row.ok_or_else(|| not_found(GroupEntityKind::Group))?
        .try_get::<i64>("", "id")
        .map_err(storage)
}

fn group_filter_conditions(filter: &GroupFilter, binds: &mut Binds) -> Vec<String> {
    let mut conditions = vec!["ug.deleted_at IS NULL".to_owned()];
    if let Some(term) = &filter.query {
        let pattern = format!("%{}%", escape_like(term));
        let placeholder = binds.push(pattern);
        conditions.push(format!(
            "(ug.name ILIKE {placeholder} OR ug.description ILIKE {placeholder} OR ug.names::text ILIKE {placeholder} OR ug.descriptions::text ILIKE {placeholder})"
        ));
    }
    if let Some(enabled) = filter.enabled {
        conditions.push(format!("ug.enabled = {}", binds.push(enabled)));
    }
    if let Some(built_in) = filter.built_in {
        conditions.push(format!("ug.built_in = {}", binds.push(built_in)));
    }
    if let Some(user_oid) = filter.user_oid {
        let placeholder = binds.push(Uuid::from(user_oid));
        conditions.push(format!(
            "EXISTS (SELECT 1 FROM group_membership gm \
                  WHERE gm.group_id = ug.id AND gm.enabled = true AND gm.revoked_at IS NULL \
                    AND gm.user_id = (SELECT id FROM \"user\" WHERE oid = {placeholder}))"
        ));
    }
    if let Some(role_oid) = filter.role_oid {
        let placeholder = binds.push(Uuid::from(role_oid));
        conditions.push(format!(
            "EXISTS (SELECT 1 FROM group_role grb \
                  JOIN \"role\" r ON r.id = grb.role_id \
                  WHERE grb.group_id = ug.id AND grb.enabled = true \
                    AND grb.revoked_at IS NULL AND r.oid = {placeholder})"
        ));
    }
    conditions
}

impl GroupManagementRepositoryImpl {
    #[tracing::instrument(skip_all, name = "db.query", fields(db.system = "postgresql", db.operation = "group.count"))]
    pub(crate) async fn group_count(
        &self,
        filter: GroupFilter,
    ) -> Result<u64, GroupManagementRepositoryError> {
        let mut binds = Binds::new();
        let conditions = group_filter_conditions(&filter, &mut binds);
        let sql = format!(
            "SELECT count(*)::bigint AS total_count FROM user_group ug WHERE {}",
            conditions.join(" AND ")
        );
        let row = self
            .db
            .query_one_raw(Statement::from_sql_and_values(
                DbBackend::Postgres,
                sql,
                binds.into_values(),
            ))
            .await
            .map_err(storage)?
            .ok_or_else(corrupt)?;
        let value = row.try_get::<i64>("", "total_count").map_err(storage)?;
        u64::try_from(value).map_err(|_| corrupt())
    }

    pub(crate) async fn group_find(
        &self,
        oid: GroupOid,
    ) -> Result<Option<GroupRecord>, GroupManagementRepositoryError> {
        load_group_by_oid(&self.db, oid).await
    }

    pub(crate) async fn membership_find(
        &self,
        oid: GroupMembershipOid,
    ) -> Result<Option<GroupMembershipRecord>, GroupManagementRepositoryError> {
        find_membership_by_oid(&self.db, oid).await
    }

    pub(crate) async fn group_role_find(
        &self,
        oid: GroupRoleBindingOid,
    ) -> Result<Option<GroupRoleBindingRecord>, GroupManagementRepositoryError> {
        find_group_role_by_oid(&self.db, oid).await
    }

    pub(crate) async fn group_list(
        &self,
        query: GroupQuery,
    ) -> Result<GroupPageData<GroupPageEntry>, GroupManagementRepositoryError> {
        let descending = order_is_descending(query.order.is_descending(), query.direction);
        let ascending = !query.order.is_descending();
        let column = match query.order {
            GroupOrder::CreatedAtAsc | GroupOrder::CreatedAtDesc => "ug.created_at",
        };
        let mut binds = Binds::new();
        let mut conditions = group_filter_conditions(&query.filter, &mut binds);
        if let Some(after) = &query.after {
            conditions.push(keyset_condition(
                column,
                "ug.id",
                after,
                CursorComparison::After,
                ascending,
                &mut binds,
            ));
        }
        if let Some(before) = &query.before {
            conditions.push(keyset_condition(
                column,
                "ug.id",
                before,
                CursorComparison::Before,
                ascending,
                &mut binds,
            ));
        }
        let direction_sql = if descending { "DESC" } else { "ASC" };
        let limit_placeholder = binds.push((query.limit + 1) as i64);
        let where_sql = conditions.join(" AND ");
        let sql = format!(
            "{GROUP_SELECT} WHERE {where_sql} \
             ORDER BY {column} {direction_sql}, ug.id {direction_sql} LIMIT {limit_placeholder}"
        );
        let rows = self
            .db
            .query_all_raw(Statement::from_sql_and_values(
                DbBackend::Postgres,
                sql,
                binds.into_values(),
            ))
            .await
            .map_err(storage)?;
        let has_more = rows.len() > query.limit;
        let mut rows = rows;
        rows.truncate(query.limit);
        if query.direction == RbacPageDirection::Backward {
            rows.reverse();
        }
        let mut items = Vec::with_capacity(rows.len());
        for row in rows {
            let id = row.try_get::<i64>("", "id").map_err(storage)?;
            let record = group_from_row(&row)?;
            let tie = RbacTie::Id(id);
            let sort_key = match query.order {
                GroupOrder::CreatedAtAsc | GroupOrder::CreatedAtDesc => RbacSortKey::CreatedAt {
                    created_at: record.created_at,
                    tie,
                },
            };
            items.push(GroupPageEntry { sort_key, record });
        }
        let (has_previous_page, has_next_page) = page_flags(
            query.direction,
            has_more,
            query.after.is_some(),
            query.before.is_some(),
        );
        Ok(GroupPageData {
            items,
            has_previous_page,
            has_next_page,
        })
    }

    pub(crate) async fn membership_list(
        &self,
        query: GroupMembershipQuery,
    ) -> Result<GroupPageData<GroupMembershipPageEntry>, GroupManagementRepositoryError> {
        let descending = order_is_descending(query.order.is_descending(), query.direction);
        let ascending = !query.order.is_descending();
        let mut binds = Binds::new();
        let group_placeholder = binds.push(Uuid::from(query.group_oid));
        let mut conditions = vec![
            format!("g.oid = {group_placeholder}"),
            "g.deleted_at IS NULL".to_owned(),
        ];
        if let Some(enabled) = query.filter.enabled {
            conditions.push(format!("gm.enabled = {}", binds.push(enabled)));
        }
        if let Some(user_oid) = query.filter.user_oid {
            conditions.push(format!("u.oid = {}", binds.push(Uuid::from(user_oid))));
        }
        if let Some(after) = &query.after {
            conditions.push(keyset_condition(
                "gm.created_at",
                "gm.id",
                after,
                CursorComparison::After,
                ascending,
                &mut binds,
            ));
        }
        if let Some(before) = &query.before {
            conditions.push(keyset_condition(
                "gm.created_at",
                "gm.id",
                before,
                CursorComparison::Before,
                ascending,
                &mut binds,
            ));
        }
        let direction_sql = if descending { "DESC" } else { "ASC" };
        let limit_placeholder = binds.push((query.limit + 1) as i64);
        let where_sql = conditions.join(" AND ");
        let sql = format!(
            "{MEMBERSHIP_SELECT} WHERE {where_sql} \
             ORDER BY gm.created_at {direction_sql}, gm.id {direction_sql} LIMIT {limit_placeholder}"
        );
        let rows = self
            .db
            .query_all_raw(Statement::from_sql_and_values(
                DbBackend::Postgres,
                sql,
                binds.into_values(),
            ))
            .await
            .map_err(storage)?;
        let has_more = rows.len() > query.limit;
        let mut rows = rows;
        rows.truncate(query.limit);
        if query.direction == RbacPageDirection::Backward {
            rows.reverse();
        }
        let mut items = Vec::with_capacity(rows.len());
        for row in rows {
            let id = row.try_get::<i64>("", "id").map_err(storage)?;
            let record = membership_from_row(&row)?;
            let sort_key = RbacSortKey::CreatedAt {
                created_at: record.created_at,
                tie: RbacTie::Id(id),
            };
            items.push(GroupMembershipPageEntry { sort_key, record });
        }
        let (has_previous_page, has_next_page) = page_flags(
            query.direction,
            has_more,
            query.after.is_some(),
            query.before.is_some(),
        );
        Ok(GroupPageData {
            items,
            has_previous_page,
            has_next_page,
        })
    }

    pub(crate) async fn role_list(
        &self,
        query: GroupRoleQuery,
    ) -> Result<GroupPageData<GroupRolePageEntry>, GroupManagementRepositoryError> {
        let descending = order_is_descending(query.order.is_descending(), query.direction);
        let ascending = !query.order.is_descending();
        let column = match query.order {
            GroupRoleOrder::CreatedAtAsc | GroupRoleOrder::CreatedAtDesc => "grb.created_at",
            GroupRoleOrder::RoleNameAsc | GroupRoleOrder::RoleNameDesc => "r.name",
        };
        let mut binds = Binds::new();
        let group_placeholder = binds.push(Uuid::from(query.group_oid));
        let mut conditions = vec![
            format!("g.oid = {group_placeholder}"),
            "g.deleted_at IS NULL".to_owned(),
        ];
        if let Some(enabled) = query.filter.enabled {
            conditions.push(format!("grb.enabled = {}", binds.push(enabled)));
        }
        if let Some(role_oid) = query.filter.role_oid {
            conditions.push(format!("r.oid = {}", binds.push(Uuid::from(role_oid))));
        }
        if let Some(after) = &query.after {
            conditions.push(keyset_condition(
                column,
                "grb.id",
                after,
                CursorComparison::After,
                ascending,
                &mut binds,
            ));
        }
        if let Some(before) = &query.before {
            conditions.push(keyset_condition(
                column,
                "grb.id",
                before,
                CursorComparison::Before,
                ascending,
                &mut binds,
            ));
        }
        let direction_sql = if descending { "DESC" } else { "ASC" };
        let limit_placeholder = binds.push((query.limit + 1) as i64);
        let where_sql = conditions.join(" AND ");
        let sql = format!(
            "{GROUP_ROLE_SELECT} WHERE {where_sql} \
             ORDER BY {column} {direction_sql}, grb.id {direction_sql} LIMIT {limit_placeholder}"
        );
        let rows = self
            .db
            .query_all_raw(Statement::from_sql_and_values(
                DbBackend::Postgres,
                sql,
                binds.into_values(),
            ))
            .await
            .map_err(storage)?;
        let has_more = rows.len() > query.limit;
        let mut rows = rows;
        rows.truncate(query.limit);
        if query.direction == RbacPageDirection::Backward {
            rows.reverse();
        }
        let mut items = Vec::with_capacity(rows.len());
        for row in rows {
            let id = row.try_get::<i64>("", "id").map_err(storage)?;
            let (record, role_name) = group_role_from_row(&row)?;
            let tie = RbacTie::Id(id);
            let sort_key = match query.order {
                GroupRoleOrder::CreatedAtAsc | GroupRoleOrder::CreatedAtDesc => {
                    RbacSortKey::CreatedAt {
                        created_at: record.created_at,
                        tie,
                    }
                }
                GroupRoleOrder::RoleNameAsc | GroupRoleOrder::RoleNameDesc => RbacSortKey::Text {
                    value: role_name,
                    tie,
                },
            };
            items.push(GroupRolePageEntry { sort_key, record });
        }
        let (has_previous_page, has_next_page) = page_flags(
            query.direction,
            has_more,
            query.after.is_some(),
            query.before.is_some(),
        );
        Ok(GroupPageData {
            items,
            has_previous_page,
            has_next_page,
        })
    }
}
