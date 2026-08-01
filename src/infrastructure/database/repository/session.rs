use async_trait::async_trait;
use chrono::{DateTime, Utc};
use sea_orm::{
    ActiveModelTrait, ColumnTrait, Condition, DatabaseConnection, EntityTrait, QueryFilter,
    QueryOrder, QuerySelect, Set, TransactionTrait,
    sea_query::{Expr, SimpleExpr},
};
use uuid::Uuid;

use super::shared::{decode_nonnullable_expiry, encode_nonnullable_expiry, lock_session};
use crate::database::entity::{
    client_authorization, client_authorization::Entity as ClientAuthorizationEntity, session,
    session::Entity as SessionEntity, user, user::Entity as UserEntity,
};
use identity_domain::auth::{
    SessionOid, SessionStatus,
    model::{ActiveSession, Session},
    repository::{CreateSessionInput, SessionRepository, SessionRepositoryError},
};
use identity_domain::client_authorization::ClientAuthorizationType;

fn session_to_domain(m: session::Model, user_oid: Uuid) -> Session {
    Session {
        oid: SessionOid(m.oid),
        user_oid,
        status: m.status,
        device_name: m.device_name,
        device_type: m.device_type,
        os_name: m.os_name,
        os_version: m.os_version,
        browser_name: m.browser_name,
        browser_version: m.browser_version,
        user_agent: m.user_agent,
        ip_address: m.ip_address,
        last_active_at: Some(m.last_active_at.with_timezone(&Utc)),
        expires_at: decode_nonnullable_expiry(m.expires_at),
        revoked_at: m.revoked_at.map(|value| value.with_timezone(&Utc)),
        created_at: m.created_at.with_timezone(&Utc),
        acr: m.acr,
        acr_expires_at: m.acr_expires_at.map(|value| value.with_timezone(&Utc)),
    }
}

pub struct SessionRepositoryImpl {
    db: DatabaseConnection,
}

#[derive(Debug, Clone, Copy)]
pub struct SessionSortKey {
    pub last_active_at: DateTime<Utc>,
    pub id: i64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionPageDirection {
    Forward,
    Backward,
}

pub struct SessionPage {
    pub items: Vec<SessionPageItem>,
    pub has_previous_page: bool,
    pub has_next_page: bool,
}

pub struct SessionPageItem {
    pub session: Session,
    pub sort_key: SessionSortKey,
}

impl SessionRepositoryImpl {
    pub fn new(db: DatabaseConnection) -> Self {
        Self { db }
    }

    pub async fn list_by_user_oid(
        &self,
        user_oid: Uuid,
    ) -> Result<Vec<Session>, SessionRepositoryError> {
        let Some(user) = UserEntity::find()
            .filter(user::Column::Oid.eq(user_oid))
            .one(&self.db)
            .await
            .map_err(|error| SessionRepositoryError::QueryFailed(Box::new(error)))?
        else {
            return Ok(Vec::new());
        };

        SessionEntity::find()
            .filter(session::Column::UserId.eq(user.id))
            .order_by_desc(session::Column::LastActiveAt)
            .order_by_desc(session::Column::Id)
            .all(&self.db)
            .await
            .map(|sessions| {
                sessions
                    .into_iter()
                    .map(|session| session_to_domain(session, user_oid))
                    .collect()
            })
            .map_err(|error| SessionRepositoryError::ListActiveFailed(Box::new(error)))
    }

    pub async fn list_page_by_user_oid(
        &self,
        user_oid: Uuid,
        after: Option<SessionSortKey>,
        before: Option<SessionSortKey>,
        limit: usize,
        direction: SessionPageDirection,
    ) -> Result<SessionPage, SessionRepositoryError> {
        let mut query = SessionEntity::find()
            .inner_join(UserEntity)
            .select_also(UserEntity)
            .filter(user::Column::Oid.eq(user_oid));
        if let Some(after) = after {
            query = query.filter(session_cursor_condition(after, CursorComparison::After));
        }
        if let Some(before) = before {
            query = query.filter(session_cursor_condition(before, CursorComparison::Before));
        }
        query = match direction {
            SessionPageDirection::Forward => query
                .order_by_desc(session::Column::LastActiveAt)
                .order_by_desc(session::Column::Id),
            SessionPageDirection::Backward => query
                .order_by_asc(session::Column::LastActiveAt)
                .order_by_asc(session::Column::Id),
        };
        let rows: Vec<(session::Model, Option<user::Model>)> = query
            .limit((limit.saturating_add(1)) as u64)
            .all(&self.db)
            .await
            .map_err(|error| SessionRepositoryError::ListActiveFailed(Box::new(error)))?;
        let items = rows
            .into_iter()
            .filter_map(|(session, user)| {
                user.map(|user| SessionPageItem {
                    sort_key: SessionSortKey {
                        last_active_at: session.last_active_at.with_timezone(&Utc),
                        id: session.id,
                    },
                    session: session_to_domain(session, user.oid),
                })
            })
            .collect::<Vec<_>>();
        Ok(build_session_page(
            items,
            limit,
            direction,
            after.is_some(),
            before.is_some(),
        ))
    }
}

fn build_session_page(
    mut items: Vec<SessionPageItem>,
    limit: usize,
    direction: SessionPageDirection,
    has_after_cursor: bool,
    has_before_cursor: bool,
) -> SessionPage {
    let has_more = items.len() > limit;
    items.truncate(limit);
    if direction == SessionPageDirection::Backward {
        items.reverse();
    }
    let (has_previous_page, has_next_page) = match direction {
        SessionPageDirection::Forward => (has_after_cursor, has_more || has_before_cursor),
        SessionPageDirection::Backward => (has_more || has_after_cursor, has_before_cursor),
    };
    SessionPage {
        items,
        has_previous_page,
        has_next_page,
    }
}

#[derive(Clone, Copy)]
enum CursorComparison {
    After,
    Before,
}

fn session_cursor_condition(cursor: SessionSortKey, comparison: CursorComparison) -> Condition {
    let last_active_at = cursor.last_active_at.fixed_offset();
    match comparison {
        CursorComparison::After => Condition::any()
            .add(session::Column::LastActiveAt.lt(last_active_at))
            .add(
                Condition::all()
                    .add(session::Column::LastActiveAt.eq(last_active_at))
                    .add(session::Column::Id.lt(cursor.id)),
            ),
        CursorComparison::Before => Condition::any()
            .add(session::Column::LastActiveAt.gt(last_active_at))
            .add(
                Condition::all()
                    .add(session::Column::LastActiveAt.eq(last_active_at))
                    .add(session::Column::Id.gt(cursor.id)),
            ),
    }
}

#[async_trait]
impl SessionRepository for SessionRepositoryImpl {
    async fn find_by_oid(
        &self,
        oid: SessionOid,
    ) -> Result<Option<Session>, SessionRepositoryError> {
        let Some((s_model, Some(u_model))) = SessionEntity::find()
            .filter(session::Column::Oid.eq(Uuid::from(oid)))
            .inner_join(UserEntity)
            .select_also(UserEntity)
            .one(&self.db)
            .await
            .map_err(|e| SessionRepositoryError::QueryFailed(Box::new(e)))?
        else {
            return Ok(None);
        };
        Ok(Some(session_to_domain(s_model, u_model.oid)))
    }

    async fn find_active_accounts_by_oids(
        &self,
        oids: &[SessionOid],
    ) -> Result<Vec<ActiveSession>, SessionRepositoryError> {
        if oids.is_empty() {
            return Ok(Vec::new());
        }
        let uuids: Vec<Uuid> = oids.iter().map(|oid| Uuid::from(*oid)).collect();
        let rows: Vec<(session::Model, Option<user::Model>)> = SessionEntity::find()
            .filter(session::Column::Oid.is_in(uuids))
            .filter(session::Column::Status.eq(SessionStatus::ACTIVE))
            .inner_join(UserEntity)
            .select_also(UserEntity)
            .all(&self.db)
            .await
            .map_err(|e| SessionRepositoryError::ListActiveFailed(Box::new(e)))?;

        Ok(rows
            .into_iter()
            .filter_map(|(s, u)| {
                let u = u?; // inner join guarantees Some, but be safe
                Some(ActiveSession {
                    session_oid: SessionOid(s.oid),
                    user_oid: u.oid,
                    user_name: u.name,
                    user_email: u.email,
                    last_active_at: Some(s.last_active_at.with_timezone(&Utc)),
                    expires_at: decode_nonnullable_expiry(s.expires_at),
                    created_at: s.created_at.with_timezone(&Utc),
                    acr: if s.acr.as_deref() == Some(identity_domain::auth::ACR_MFA)
                        && s.acr_expires_at
                            .is_some_and(|expires_at| expires_at.with_timezone(&Utc) <= Utc::now())
                    {
                        Some(identity_domain::auth::ACR_PASSWORD.to_owned())
                    } else {
                        s.acr
                    },
                })
            })
            .collect())
    }

    async fn create(&self, input: CreateSessionInput) -> Result<Session, SessionRepositoryError> {
        let user = UserEntity::find()
            .filter(user::Column::Oid.eq(input.user_oid))
            .one(&self.db)
            .await
            .map_err(|e| SessionRepositoryError::QueryFailed(Box::new(e)))?
            .ok_or(SessionRepositoryError::UserNotFound)?;

        let now = Utc::now();
        let active = session::ActiveModel {
            oid: Set(Uuid::new_v4()),
            user_id: Set(user.id),
            status: Set(SessionStatus::ACTIVE.to_owned()),
            device_name: Set(input.device_name),
            device_type: Set(input.device_type),
            os_name: Set(input.os_name),
            os_version: Set(input.os_version),
            browser_name: Set(input.browser_name),
            browser_version: Set(input.browser_version),
            user_agent: Set(input.user_agent),
            ip_address: Set(input.ip_address),
            last_active_at: Set(now.into()),
            expires_at: Set(encode_nonnullable_expiry(input.expires_at)),
            created_at: Set(now.into()),
            updated_at: Set(Some(now.into())),
            acr: Set(input.acr),
            acr_expires_at: Set(input.acr_expires_at.map(Into::into)),
            ..Default::default()
        };
        let model = active
            .insert(&self.db)
            .await
            .map_err(|e| SessionRepositoryError::CreateFailed(Box::new(e)))?;
        Ok(session_to_domain(model, input.user_oid))
    }

    async fn touch_by_oid(&self, oid: SessionOid) -> Result<(), SessionRepositoryError> {
        let model = SessionEntity::find()
            .filter(session::Column::Oid.eq(Uuid::from(oid)))
            .one(&self.db)
            .await
            .map_err(|e| SessionRepositoryError::QueryFailed(Box::new(e)))?
            .ok_or(SessionRepositoryError::SessionNotFound)?;

        let mut active: session::ActiveModel = model.into();
        active.last_active_at = Set(Utc::now().into());
        active
            .update(&self.db)
            .await
            .map_err(|e| SessionRepositoryError::TouchFailed(Box::new(e)))?;
        Ok(())
    }

    async fn revoke_by_oid(
        &self,
        oid: SessionOid,
        revoked_at: DateTime<Utc>,
    ) -> Result<Option<Session>, SessionRepositoryError> {
        let transaction = self
            .db
            .begin()
            .await
            .map_err(|error| SessionRepositoryError::RevokeFailed(Box::new(error)))?;
        lock_session(&transaction, oid)
            .await
            .map_err(|error| SessionRepositoryError::RevokeFailed(Box::new(error)))?;
        let Some((s_model, Some(u_model))) = SessionEntity::find()
            .filter(session::Column::Oid.eq(Uuid::from(oid)))
            .inner_join(UserEntity)
            .select_also(UserEntity)
            .one(&transaction)
            .await
            .map_err(|e| SessionRepositoryError::QueryFailed(Box::new(e)))?
        else {
            return Ok(None);
        };

        let mut active: session::ActiveModel = s_model.into();
        active.revoked_at = Set(Some(revoked_at.into()));
        active.status = Set(SessionStatus::REVOKED.to_owned());
        active.updated_at = Set(Some(revoked_at.into()));
        let model = active
            .update(&transaction)
            .await
            .map_err(|e| SessionRepositoryError::RevokeFailed(Box::new(e)))?;
        ClientAuthorizationEntity::update_many()
            .col_expr(
                client_authorization::Column::RevokedAt,
                SimpleExpr::Value(Some(revoked_at).into()),
            )
            .col_expr(
                client_authorization::Column::UpdatedAt,
                SimpleExpr::Value(Some(revoked_at).into()),
            )
            .filter(
                Condition::all()
                    .add(client_authorization::Column::RevokedAt.is_null())
                    .add(client_authorization::Column::Type.is_in([
                        ClientAuthorizationType::AuthorizationCode.to_string(),
                        ClientAuthorizationType::AccessToken.to_string(),
                        ClientAuthorizationType::RefreshToken.to_string(),
                    ]))
                    .add(Expr::cust_with_values(
                        r#"("client_authorization"."data"->>'session_oid') = $1"#,
                        [Uuid::from(oid).to_string()],
                    )),
            )
            .exec(&transaction)
            .await
            .map_err(|error| SessionRepositoryError::RevokeFailed(Box::new(error)))?;
        transaction
            .commit()
            .await
            .map_err(|error| SessionRepositoryError::RevokeFailed(Box::new(error)))?;
        Ok(Some(session_to_domain(model, u_model.oid)))
    }
}

#[cfg(test)]
mod tests {
    use sea_orm::{DbBackend, EntityTrait as _, QueryFilter as _, QueryTrait as _};

    use super::{
        CursorComparison, SessionPageItem, SessionSortKey, session_cursor_condition,
        session_to_domain,
    };
    use chrono::{DateTime, Utc};
    use uuid::Uuid;

    use crate::database::entity::session;
    use identity_domain::auth::{SessionOid, SessionStatus, model::Session};

    #[test]
    fn session_to_domain_wraps_required_timestamps_in_some() {
        let last_active_at = DateTime::parse_from_rfc3339("2026-01-01T01:00:00+00:00").unwrap();
        let expires_at = DateTime::parse_from_rfc3339("2026-01-08T01:00:00+00:00").unwrap();
        let created_at = DateTime::parse_from_rfc3339("2026-01-01T00:00:00+00:00").unwrap();
        let model = session::Model {
            id: 1,
            oid: Uuid::new_v4(),
            user_id: 42,
            status: SessionStatus::ACTIVE.to_owned(),
            acr: None,
            acr_expires_at: None,
            device_name: None,
            device_type: None,
            os_name: None,
            os_version: None,
            browser_name: None,
            browser_version: None,
            user_agent: None,
            ip_address: None,
            country: None,
            city: None,
            last_active_at,
            expires_at,
            revoked_at: None,
            created_at,
            updated_at: None,
        };

        let session = session_to_domain(model, Uuid::new_v4());

        assert_eq!(
            session.last_active_at,
            Some(last_active_at.with_timezone(&Utc))
        );
        assert_eq!(session.expires_at, Some(expires_at.with_timezone(&Utc)));
        assert_eq!(session.created_at, created_at.with_timezone(&Utc));
    }

    #[test]
    fn relay_cursor_filter_uses_the_complete_stable_sort_key() {
        let cursor = SessionSortKey {
            last_active_at: "2026-08-01T12:00:00Z".parse().unwrap(),
            id: 42,
        };
        let statement = session::Entity::find()
            .filter(session_cursor_condition(cursor, CursorComparison::After))
            .build(DbBackend::Postgres)
            .to_string();

        assert!(statement.contains(r#""session"."last_active_at" <"#));
        assert!(statement.contains(r#""session"."id" <"#));
        assert!(statement.contains(" OR "));
    }

    #[test]
    fn backward_relay_page_restores_connection_order_and_reports_boundaries() {
        let first_oid = Uuid::from_u128(1);
        let second_oid = Uuid::from_u128(2);
        let third_oid = Uuid::from_u128(3);
        let page = super::build_session_page(
            vec![
                page_item(1, first_oid),
                page_item(2, second_oid),
                page_item(3, third_oid),
            ],
            2,
            super::SessionPageDirection::Backward,
            false,
            true,
        );

        assert_eq!(
            page.items
                .iter()
                .map(|item| Uuid::from(item.session.oid))
                .collect::<Vec<_>>(),
            vec![second_oid, first_oid]
        );
        assert!(page.has_previous_page);
        assert!(page.has_next_page);
    }

    #[test]
    fn first_relay_page_only_reports_a_next_page_when_one_more_row_exists() {
        let page = super::build_session_page(
            vec![
                page_item(3, Uuid::from_u128(3)),
                page_item(2, Uuid::from_u128(2)),
                page_item(1, Uuid::from_u128(1)),
            ],
            2,
            super::SessionPageDirection::Forward,
            false,
            false,
        );

        assert!(!page.has_previous_page);
        assert!(page.has_next_page);
    }

    fn domain_session(oid: Uuid) -> Session {
        let now = Utc::now();
        Session {
            oid: SessionOid(oid),
            user_oid: Uuid::nil(),
            status: SessionStatus::ACTIVE.to_owned(),
            device_name: None,
            device_type: None,
            os_name: None,
            os_version: None,
            browser_name: None,
            browser_version: None,
            user_agent: None,
            ip_address: None,
            last_active_at: Some(now),
            expires_at: None,
            revoked_at: None,
            created_at: now,
            acr: None,
            acr_expires_at: None,
        }
    }

    fn page_item(id: i64, oid: Uuid) -> SessionPageItem {
        let session = domain_session(oid);
        SessionPageItem {
            sort_key: SessionSortKey {
                last_active_at: session.last_active_at.unwrap(),
                id,
            },
            session,
        }
    }
}
