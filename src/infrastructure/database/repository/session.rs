use async_trait::async_trait;
use chrono::{DateTime, Utc};
use sea_orm::{ActiveModelTrait, ColumnTrait, DatabaseConnection, EntityTrait, QueryFilter, Set};
use uuid::Uuid;

use super::shared::{decode_nonnullable_expiry, encode_nonnullable_expiry};
use crate::database::entity::{
    session, session::Entity as SessionEntity, user, user::Entity as UserEntity,
};
use identity_domain::auth::{
    SessionOid, SessionStatus,
    model::{ActiveSession, Session},
    repository::{SessionRepository, SessionRepositoryError},
};

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

impl SessionRepositoryImpl {
    pub fn new(db: DatabaseConnection) -> Self {
        Self { db }
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
                })
            })
            .collect())
    }

    async fn create(
        &self,
        user_oid: Uuid,
        device_name: Option<String>,
        device_type: Option<String>,
        os_name: Option<String>,
        os_version: Option<String>,
        browser_name: Option<String>,
        browser_version: Option<String>,
        user_agent: Option<String>,
        ip_address: Option<String>,
        expires_at: Option<DateTime<Utc>>,
        acr: Option<String>,
        acr_expires_at: Option<DateTime<Utc>>,
    ) -> Result<Session, SessionRepositoryError> {
        let user = UserEntity::find()
            .filter(user::Column::Oid.eq(user_oid))
            .one(&self.db)
            .await
            .map_err(|e| SessionRepositoryError::QueryFailed(Box::new(e)))?
            .ok_or(SessionRepositoryError::UserNotFound)?;

        let now = Utc::now();
        let active = session::ActiveModel {
            oid: Set(Uuid::new_v4()),
            user_id: Set(user.id),
            status: Set(SessionStatus::ACTIVE.to_owned()),
            device_name: Set(device_name),
            device_type: Set(device_type),
            os_name: Set(os_name),
            os_version: Set(os_version),
            browser_name: Set(browser_name),
            browser_version: Set(browser_version),
            user_agent: Set(user_agent),
            ip_address: Set(ip_address),
            last_active_at: Set(now.into()),
            expires_at: Set(encode_nonnullable_expiry(expires_at)),
            created_at: Set(now.into()),
            updated_at: Set(Some(now.into())),
            acr: Set(acr),
            acr_expires_at: Set(acr_expires_at.map(Into::into)),
            ..Default::default()
        };
        let model = active
            .insert(&self.db)
            .await
            .map_err(|e| SessionRepositoryError::CreateFailed(Box::new(e)))?;
        Ok(session_to_domain(model, user_oid))
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

        let mut active: session::ActiveModel = s_model.into();
        active.revoked_at = Set(Some(revoked_at.into()));
        let model = active
            .update(&self.db)
            .await
            .map_err(|e| SessionRepositoryError::RevokeFailed(Box::new(e)))?;
        Ok(Some(session_to_domain(model, u_model.oid)))
    }
}

#[cfg(test)]
mod tests {
    use super::session_to_domain;
    use chrono::{DateTime, Utc};
    use uuid::Uuid;

    use crate::database::entity::session;
    use identity_domain::auth::SessionStatus;

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
}
