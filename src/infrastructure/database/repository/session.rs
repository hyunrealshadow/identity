use async_trait::async_trait;
use chrono::{DateTime, Utc};
use sea_orm::{
    ActiveModelTrait, ColumnTrait, Condition, DatabaseConnection, EntityTrait, QueryFilter,
    QueryOrder, Set, TransactionTrait,
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
            .order_by_desc(session::Column::CreatedAt)
            .order_by_desc(session::Column::Oid)
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
