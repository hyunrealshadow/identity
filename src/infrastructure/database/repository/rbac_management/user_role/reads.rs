//! User role bindings, effective permissions and account summaries as read models.

use super::*;

impl RbacManagementRepositoryImpl {
    pub(crate) async fn user_version(
        &self,
        user_oid: UserOid,
    ) -> Result<Uuid, RbacManagementRepositoryError> {
        let Some(user_id) = user_id_by_oid(&self.db, user_oid).await? else {
            return Err(not_found(RbacEntityKind::User));
        };
        let row = self
            .db
            .query_one_raw(Statement::from_sql_and_values(
                DbBackend::Postgres,
                "SELECT version FROM \"user\" WHERE id = $1",
                [user_id.into()],
            ))
            .await
            .map_err(storage)?
            .ok_or_else(corrupt)?;
        row.try_get::<Uuid>("", "version").map_err(storage)
    }

    pub(crate) async fn user_role_list(
        &self,
        query: UserRoleQuery,
    ) -> Result<UserRolePageData, RbacManagementRepositoryError> {
        // Page rows and the single-user version are read from one
        // REPEATABLE READ snapshot. A separate version query after the page
        // would let a concurrent assignment revoke the cursor's CAS metadata.
        let txn = self.db.begin().await.map_err(storage)?;
        txn.execute_raw(Statement::from_string(
            DbBackend::Postgres,
            "SET TRANSACTION ISOLATION LEVEL REPEATABLE READ".to_owned(),
        ))
        .await
        .map_err(storage)?;
        let user_version = match query.user_oid {
            Some(user_oid) => {
                let Some(user_id) = user_id_by_oid(&txn, user_oid).await? else {
                    return Err(not_found(RbacEntityKind::User));
                };
                Some(current_user_version(&txn, user_id).await?)
            }
            None => None,
        };
        let descending = order_is_descending(query.order.is_descending(), query.direction);
        let ascending = !query.order.is_descending();
        let mut binds = Binds::new();
        let mut conditions = vec!["1=1".to_owned()];
        if let Some(user_oid) = query.user_oid {
            conditions.push(format!("u.oid = {}", binds.push(Uuid::from(user_oid))));
        }
        if let Some(role_oid) = query.role_oid {
            conditions.push(format!("r.oid = {}", binds.push(Uuid::from(role_oid))));
        }
        if let Some(enabled) = query.enabled {
            conditions.push(format!("urb.enabled = {}", binds.push(enabled)));
        }
        if let Some(after) = &query.after {
            conditions.push(keyset_condition(
                "urb.created_at",
                "urb.id",
                after,
                CursorComparison::After,
                ascending,
                &mut binds,
            ));
        }
        if let Some(before) = &query.before {
            conditions.push(keyset_condition(
                "urb.created_at",
                "urb.id",
                before,
                CursorComparison::Before,
                ascending,
                &mut binds,
            ));
        }
        let direction_sql = if descending { "DESC" } else { "ASC" };
        let limit_placeholder = binds.push(
            crate::database::repository::shared::page_fetch_limit_i64(query.limit)
                .map_err(storage)?,
        );
        let where_sql = conditions.join(" AND ");
        let sql = format!(
            "{BINDING_SELECT} WHERE {where_sql} \
             ORDER BY urb.created_at {direction_sql}, urb.id {direction_sql} LIMIT {limit_placeholder}"
        );
        let rows = txn
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
            let record = binding_from_row(&row)?;
            let sort_key = RbacSortKey::CreatedAt {
                created_at: record.created_at,
                tie: RbacTie::Id(id),
            };
            items.push(UserRolePageEntry { sort_key, record });
        }
        let (has_previous_page, has_next_page) = page_flags(
            query.direction,
            has_more,
            query.after.is_some(),
            query.before.is_some(),
        );
        txn.commit().await.map_err(storage)?;
        Ok(UserRolePageData {
            items,
            has_previous_page,
            has_next_page,
            user_version,
        })
    }

    #[tracing::instrument(skip_all, name = "db.query", fields(db.operation = "user_role_grant_list"))]
    pub(crate) async fn user_role_grant_list(
        &self,
        query: UserRoleGrantQuery,
    ) -> Result<UserRoleGrantPageData, RbacManagementRepositoryError> {
        // Rows and the user version come from one REPEATABLE READ snapshot so
        // the version stays valid as the CAS input for this page.
        let txn = self.db.begin().await.map_err(storage)?;
        txn.execute_raw(Statement::from_string(
            DbBackend::Postgres,
            "SET TRANSACTION ISOLATION LEVEL REPEATABLE READ".to_owned(),
        ))
        .await
        .map_err(storage)?;
        let Some(user_id) = user_id_by_oid(&txn, query.user_oid).await? else {
            return Err(not_found(RbacEntityKind::User));
        };
        let user_version = current_user_version(&txn, user_id).await?;
        let descending = order_is_descending(query.order.is_descending(), query.direction);
        let ascending = !query.order.is_descending();
        let mut binds = Binds::new();
        let user_placeholder = binds.push(user_id);
        let include_direct = query.source != Some(AuthorizationSource::Group);
        // Inherited roles are live grants; they have no revoked history.
        let include_group =
            query.source != Some(AuthorizationSource::Direct) && query.enabled != Some(false);
        let mut parts = Vec::with_capacity(2);
        if include_direct {
            let enabled = query.enabled.map(|enabled| binds.push(enabled));
            parts.push(direct_grant_select(&user_placeholder, enabled.as_deref()));
        }
        if include_group {
            parts.push(group_grant_select(&user_placeholder));
        }
        if parts.is_empty() {
            txn.commit().await.map_err(storage)?;
            return Ok(UserRoleGrantPageData {
                items: Vec::new(),
                has_previous_page: false,
                has_next_page: false,
                user_version,
            });
        }
        let mut conditions = vec!["1=1".to_owned()];
        if let Some(after) = &query.after {
            conditions.push(keyset_condition(
                "g.granted_at",
                "g.tie_oid",
                after,
                CursorComparison::After,
                ascending,
                &mut binds,
            ));
        }
        if let Some(before) = &query.before {
            conditions.push(keyset_condition(
                "g.granted_at",
                "g.tie_oid",
                before,
                CursorComparison::Before,
                ascending,
                &mut binds,
            ));
        }
        let direction_sql = if descending { "DESC" } else { "ASC" };
        let limit_placeholder = binds.push(
            crate::database::repository::shared::page_fetch_limit_i64(query.limit)
                .map_err(storage)?,
        );
        let sql = format!(
            "SELECT g.* FROM ({}) g WHERE {} \
             ORDER BY g.granted_at {direction_sql}, g.tie_oid {direction_sql} LIMIT {limit_placeholder}",
            parts.join(" UNION ALL "),
            conditions.join(" AND "),
        );
        let rows = txn
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
            let tie_oid = row.try_get::<Uuid>("", "tie_oid").map_err(storage)?;
            let created_at = utc(row
                .try_get::<chrono::DateTime<chrono::FixedOffset>>("", "granted_at")
                .map_err(storage)?);
            let role_oid = RoleOid(row.try_get::<Uuid>("", "role_oid").map_err(storage)?);
            let kind = row.try_get::<String>("", "kind").map_err(storage)?;
            let grant = match kind.as_str() {
                "direct" => UserRoleGrant::Direct(UserRoleRecord {
                    oid: UserRoleOid(tie_oid),
                    user_oid: query.user_oid,
                    role_oid,
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
                    version: row
                        .try_get::<Option<Uuid>>("", "version")
                        .map_err(storage)?
                        .ok_or_else(corrupt)?,
                    user_version,
                    created_at,
                    updated_at: row
                        .try_get::<Option<chrono::DateTime<chrono::FixedOffset>>>("", "updated_at")
                        .map_err(storage)?
                        .map(utc),
                }),
                "group" => UserRoleGrant::Group(InheritedUserRoleRecord {
                    user_oid: query.user_oid,
                    role_oid,
                    group_oid: GroupOid(
                        row.try_get::<Option<Uuid>>("", "group_oid")
                            .map_err(storage)?
                            .ok_or_else(corrupt)?,
                    ),
                    membership_oid: GroupMembershipOid(
                        row.try_get::<Option<Uuid>>("", "membership_oid")
                            .map_err(storage)?
                            .ok_or_else(corrupt)?,
                    ),
                    group_role_oid: GroupRoleOid(tie_oid),
                    created_at,
                }),
                _ => return Err(corrupt()),
            };
            let sort_key = RbacSortKey::CreatedAt {
                created_at,
                tie: RbacTie::Oid(tie_oid),
            };
            items.push(UserRoleGrantPageEntry { sort_key, grant });
        }
        let (has_previous_page, has_next_page) = page_flags(
            query.direction,
            has_more,
            query.after.is_some(),
            query.before.is_some(),
        );
        txn.commit().await.map_err(storage)?;
        Ok(UserRoleGrantPageData {
            items,
            has_previous_page,
            has_next_page,
            user_version,
        })
    }

    #[tracing::instrument(skip_all, name = "db.query", fields(db.operation = "effective_permission_count"))]
    pub(crate) async fn effective_count(
        &self,
        user_oid: UserOid,
        resource_oid: ResourceOid,
        source: Option<AuthorizationSource>,
    ) -> Result<u64, RbacManagementRepositoryError> {
        let txn = self.db.begin().await.map_err(storage)?;
        let user_id = user_id_by_oid(&txn, user_oid)
            .await?
            .ok_or_else(|| not_found(RbacEntityKind::User))?;
        let resource = txn
            .query_one_raw(Statement::from_sql_and_values(
                DbBackend::Postgres,
                "SELECT uri, enabled FROM resource WHERE oid = $1",
                [Uuid::from(resource_oid).into()],
            ))
            .await
            .map_err(storage)?
            .ok_or_else(|| not_found(RbacEntityKind::Resource))?;
        if !resource.try_get::<bool>("", "enabled").map_err(storage)? {
            txn.commit().await.map_err(storage)?;
            return Ok(0);
        }
        let management_resource =
            resource.try_get::<String>("", "uri").map_err(storage)? == API_RESOURCE;
        let mut binds = Binds::new();
        let conditions = effective_permission_conditions(
            user_id,
            resource_oid,
            management_resource,
            source,
            &mut binds,
        );
        let row = txn
            .query_one_raw(Statement::from_sql_and_values(
                DbBackend::Postgres,
                format!(
                    "SELECT count(*)::bigint AS total_count FROM scope s WHERE {}",
                    conditions.join(" AND ")
                ),
                binds.into_values(),
            ))
            .await
            .map_err(storage)?
            .ok_or_else(corrupt)?;
        let total = u64::try_from(row.try_get::<i64>("", "total_count").map_err(storage)?)
            .map_err(|_| corrupt())?;
        txn.commit().await.map_err(storage)?;
        Ok(total)
    }

    pub(crate) async fn effective_list(
        &self,
        query: EffectivePermissionQuery,
    ) -> Result<EffectivePermissionPageData, RbacManagementRepositoryError> {
        let txn = self.db.begin().await.map_err(storage)?;
        let Some(user_id) = user_id_by_oid(&txn, query.user_oid).await? else {
            return Err(not_found(RbacEntityKind::User));
        };
        let version = current_user_version(&txn, user_id).await?;
        let resource_row = txn
            .query_one_raw(Statement::from_sql_and_values(
                DbBackend::Postgres,
                "SELECT uri, enabled FROM resource WHERE oid = $1",
                [Uuid::from(query.resource_oid).into()],
            ))
            .await
            .map_err(storage)?
            .ok_or_else(|| not_found(RbacEntityKind::Resource))?;
        let management_resource =
            resource_row.try_get::<String>("", "uri").map_err(storage)? == API_RESOURCE;
        let enabled = resource_row
            .try_get::<bool>("", "enabled")
            .map_err(storage)?;
        if !enabled {
            txn.commit().await.map_err(storage)?;
            return Ok(EffectivePermissionPageData {
                items: Vec::new(),
                has_previous_page: false,
                has_next_page: false,
                user_version: version,
            });
        }
        let descending = order_is_descending(query.order.is_descending(), query.direction);
        let ascending = !query.order.is_descending();
        let mut binds = Binds::new();
        let mut conditions = effective_permission_conditions(
            user_id,
            query.resource_oid,
            management_resource,
            query.source,
            &mut binds,
        );
        if let Some(after) = &query.after {
            conditions.push(keyset_condition(
                "s.code",
                "s.id",
                after,
                CursorComparison::After,
                ascending,
                &mut binds,
            ));
        }
        if let Some(before) = &query.before {
            conditions.push(keyset_condition(
                "s.code",
                "s.id",
                before,
                CursorComparison::Before,
                ascending,
                &mut binds,
            ));
        }
        let direction_sql = if descending { "DESC" } else { "ASC" };
        let limit_placeholder = binds.push(
            crate::database::repository::shared::page_fetch_limit_i64(query.limit)
                .map_err(storage)?,
        );
        let where_sql = conditions.join(" AND ");
        let sql = format!(
            "SELECT s.id, s.oid AS permission_oid, s.resource_id, s.code, s.code AS scope \
             FROM \"scope\" s WHERE {where_sql} \
             ORDER BY s.code {direction_sql}, s.id {direction_sql} LIMIT {limit_placeholder}"
        );
        let rows = txn
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
        let permission_ids = rows
            .iter()
            .map(|row| row.try_get::<i64>("", "id"))
            .collect::<Result<Vec<_>, _>>()
            .map_err(storage)?;
        let sources = load_direct_permission_sources(&txn, user_id, &permission_ids).await?;
        let group_sources = load_group_permission_sources(&txn, user_id, &permission_ids).await?;
        let mut items = Vec::with_capacity(rows.len());
        for row in rows {
            let id = row.try_get::<i64>("", "id").map_err(storage)?;
            let record = EffectivePermissionRecord {
                permission_oid: ResourcePermissionOid(
                    row.try_get::<Uuid>("", "permission_oid").map_err(storage)?,
                ),
                resource_oid: ResourceOid(
                    row.try_get::<Option<Uuid>>("", "resource_id")
                        .map_err(storage)?
                        .ok_or_else(corrupt)?,
                ),
                code: row.try_get::<String>("", "code").map_err(storage)?,
                scope: row.try_get::<String>("", "scope").map_err(storage)?,
                sources: sources.get(&id).cloned().unwrap_or_default(),
                group_sources: group_sources.get(&id).cloned().unwrap_or_default(),
            };
            let sort_key = RbacSortKey::Text {
                value: record.code.clone(),
                tie: RbacTie::Id(id),
            };
            items.push(EffectivePermissionPageEntry { sort_key, record });
        }
        let (has_previous_page, has_next_page) = page_flags(
            query.direction,
            has_more,
            query.after.is_some(),
            query.before.is_some(),
        );
        txn.commit().await.map_err(storage)?;
        Ok(EffectivePermissionPageData {
            items,
            has_previous_page,
            has_next_page,
            user_version: version,
        })
    }

    #[tracing::instrument(skip_all, name = "db.query", fields(db.operation = "account_roles.count"))]
    pub(crate) async fn account_role_count(
        &self,
        user_oid: UserOid,
        source: Option<AuthorizationSource>,
    ) -> Result<u64, RbacManagementRepositoryError> {
        let Some(user_id) = active_user_id_by_oid(&self.db, user_oid).await? else {
            return Ok(0);
        };
        let mut binds = Binds::new();
        let user_placeholder = binds.push(user_id);
        let union_sql = account_role_union(&user_placeholder, source);
        let row = self
            .db
            .query_one_raw(Statement::from_sql_and_values(
                DbBackend::Postgres,
                format!("SELECT count(*)::bigint AS total_count FROM ({union_sql}) g"),
                binds.into_values(),
            ))
            .await
            .map_err(storage)?
            .ok_or_else(corrupt)?;
        let total = row.try_get::<i64>("", "total_count").map_err(storage)?;
        u64::try_from(total).map_err(|_| corrupt())
    }

    #[tracing::instrument(skip_all, name = "db.query", fields(db.operation = "account_roles.list"))]
    pub(crate) async fn account_role_list(
        &self,
        query: AccountRoleQuery,
    ) -> Result<RbacPageData<AccountRolePageEntry>, RbacManagementRepositoryError> {
        let Some(user_id) = active_user_id_by_oid(&self.db, query.user_oid).await? else {
            return Ok(RbacPageData {
                items: Vec::new(),
                has_previous_page: false,
                has_next_page: false,
            });
        };
        let descending = order_is_descending(query.order.is_descending(), query.direction);
        let ascending = !query.order.is_descending();
        let mut binds = Binds::new();
        let user_placeholder = binds.push(user_id);
        let union_sql = account_role_union(&user_placeholder, query.source);
        let mut conditions = vec!["1=1".to_owned()];
        if let Some(after) = &query.after {
            conditions.push(keyset_condition(
                "g.granted_at",
                "g.tie_oid",
                after,
                CursorComparison::After,
                ascending,
                &mut binds,
            ));
        }
        if let Some(before) = &query.before {
            conditions.push(keyset_condition(
                "g.granted_at",
                "g.tie_oid",
                before,
                CursorComparison::Before,
                ascending,
                &mut binds,
            ));
        }
        let direction_sql = if descending { "DESC" } else { "ASC" };
        let limit_placeholder = binds.push(
            crate::database::repository::shared::page_fetch_limit_i64(query.limit)
                .map_err(storage)?,
        );
        let sql = format!(
            "SELECT g.* FROM ({union_sql}) g WHERE {} \
             ORDER BY g.granted_at {direction_sql}, g.tie_oid {direction_sql} LIMIT {limit_placeholder}",
            conditions.join(" AND ")
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
            let tie_oid = row.try_get::<Uuid>("", "tie_oid").map_err(storage)?;
            let granted_at = utc(row
                .try_get::<chrono::DateTime<chrono::FixedOffset>>("", "granted_at")
                .map_err(storage)?);
            let role_oid = RoleOid(row.try_get::<Uuid>("", "role_oid").map_err(storage)?);
            let kind = row.try_get::<String>("", "kind").map_err(storage)?;
            let grant = match kind.as_str() {
                "direct" => AccountRoleGrant::Direct {
                    role_oid,
                    granted_at,
                },
                "group" => AccountRoleGrant::Group {
                    role_oid,
                    group_oid: GroupOid(
                        row.try_get::<Option<Uuid>>("", "group_oid")
                            .map_err(storage)?
                            .ok_or_else(corrupt)?,
                    ),
                    granted_at,
                },
                _ => return Err(corrupt()),
            };
            let sort_key = RbacSortKey::CreatedAt {
                created_at: granted_at,
                tie: RbacTie::Oid(tie_oid),
            };
            items.push(AccountRolePageEntry { sort_key, grant });
        }
        let (has_previous_page, has_next_page) = page_flags(
            query.direction,
            has_more,
            query.after.is_some(),
            query.before.is_some(),
        );
        Ok(RbacPageData {
            items,
            has_previous_page,
            has_next_page,
        })
    }

    #[tracing::instrument(skip_all, name = "db.query", fields(db.operation = "account_permissions.count"))]
    pub(crate) async fn account_permission_count(
        &self,
        user_oid: UserOid,
        resource_oid: Option<ResourceOid>,
        source: Option<AuthorizationSource>,
    ) -> Result<u64, RbacManagementRepositoryError> {
        let txn = self.db.begin().await.map_err(storage)?;
        let Some(user_id) = active_user_id_by_oid(&txn, user_oid).await? else {
            txn.commit().await.map_err(storage)?;
            return Ok(0);
        };
        let mut binds = Binds::new();
        let conditions = account_permission_conditions(user_id, resource_oid, source, &mut binds);
        let row = txn
            .query_one_raw(Statement::from_sql_and_values(
                DbBackend::Postgres,
                format!(
                    "SELECT count(*)::bigint AS total_count \
                     FROM \"scope\" s \
                     JOIN resource res ON res.oid = s.resource_id \
                     WHERE {}",
                    conditions.join(" AND ")
                ),
                binds.into_values(),
            ))
            .await
            .map_err(storage)?
            .ok_or_else(corrupt)?;
        let total = u64::try_from(row.try_get::<i64>("", "total_count").map_err(storage)?)
            .map_err(|_| corrupt())?;
        txn.commit().await.map_err(storage)?;
        Ok(total)
    }

    #[tracing::instrument(skip_all, name = "db.query", fields(db.operation = "account_permissions.list"))]
    pub(crate) async fn account_permission_list(
        &self,
        query: AccountPermissionQuery,
    ) -> Result<RbacPageData<AccountPermissionPageEntry>, RbacManagementRepositoryError> {
        let txn = self.db.begin().await.map_err(storage)?;
        txn.execute_raw(Statement::from_string(
            DbBackend::Postgres,
            "SET TRANSACTION ISOLATION LEVEL REPEATABLE READ".to_owned(),
        ))
        .await
        .map_err(storage)?;
        let Some(user_id) = active_user_id_by_oid(&txn, query.user_oid).await? else {
            txn.commit().await.map_err(storage)?;
            return Ok(RbacPageData {
                items: Vec::new(),
                has_previous_page: false,
                has_next_page: false,
            });
        };
        let descending = order_is_descending(query.order.is_descending(), query.direction);
        let ascending = !query.order.is_descending();
        let mut binds = Binds::new();
        let mut conditions =
            account_permission_conditions(user_id, query.resource_oid, query.source, &mut binds);
        if let Some(after) = &query.after {
            conditions.push(keyset_condition(
                "s.code",
                "s.id",
                after,
                CursorComparison::After,
                ascending,
                &mut binds,
            ));
        }
        if let Some(before) = &query.before {
            conditions.push(keyset_condition(
                "s.code",
                "s.id",
                before,
                CursorComparison::Before,
                ascending,
                &mut binds,
            ));
        }
        let direction_sql = if descending { "DESC" } else { "ASC" };
        let limit_placeholder = binds.push(
            crate::database::repository::shared::page_fetch_limit_i64(query.limit)
                .map_err(storage)?,
        );
        let where_sql = conditions.join(" AND ");
        let sql = format!(
            "SELECT s.id, s.oid AS permission_oid, s.resource_id, \
                    res.uri AS resource_uri, res.name AS resource_name, \
                    s.code, s.name, s.names, s.description, s.descriptions, s.built_in \
             FROM \"scope\" s \
             JOIN resource res ON res.oid = s.resource_id \
             WHERE {where_sql} \
             ORDER BY s.code {direction_sql}, s.id {direction_sql} LIMIT {limit_placeholder}"
        );
        let rows = txn
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
        let permission_ids = rows
            .iter()
            .map(|row| row.try_get::<i64>("", "id"))
            .collect::<Result<Vec<_>, _>>()
            .map_err(storage)?;
        let sources = load_direct_permission_sources(&txn, user_id, &permission_ids).await?;
        let group_sources = load_group_permission_sources(&txn, user_id, &permission_ids).await?;
        let mut items = Vec::with_capacity(rows.len());
        for row in rows {
            let id = row.try_get::<i64>("", "id").map_err(storage)?;
            let metadata = parse_localized_metadata(
                row.try_get::<serde_json::Value>("", "names")
                    .map_err(storage)?,
                row.try_get::<serde_json::Value>("", "descriptions")
                    .map_err(storage)?,
            )?;
            let code = row.try_get::<String>("", "code").map_err(storage)?;
            let record = AccountPermissionRecord {
                permission_oid: ResourcePermissionOid(
                    row.try_get::<Uuid>("", "permission_oid").map_err(storage)?,
                ),
                resource_oid: ResourceOid(
                    row.try_get::<Option<Uuid>>("", "resource_id")
                        .map_err(storage)?
                        .ok_or_else(corrupt)?,
                ),
                resource_uri: row.try_get::<String>("", "resource_uri").map_err(storage)?,
                resource_name: row
                    .try_get::<String>("", "resource_name")
                    .map_err(storage)?,
                scope: code.clone(),
                code,
                name: row.try_get::<String>("", "name").map_err(storage)?,
                names: metadata.names,
                description: row.try_get::<String>("", "description").map_err(storage)?,
                descriptions: metadata.descriptions,
                built_in: row.try_get::<bool>("", "built_in").map_err(storage)?,
                sources: sources.get(&id).cloned().unwrap_or_default(),
                group_sources: group_sources.get(&id).cloned().unwrap_or_default(),
            };
            let sort_key = RbacSortKey::Text {
                value: record.code.clone(),
                tie: RbacTie::Id(id),
            };
            items.push(AccountPermissionPageEntry { sort_key, record });
        }
        let (has_previous_page, has_next_page) = page_flags(
            query.direction,
            has_more,
            query.after.is_some(),
            query.before.is_some(),
        );
        txn.commit().await.map_err(storage)?;
        Ok(RbacPageData {
            items,
            has_previous_page,
            has_next_page,
        })
    }
}
