use async_trait::async_trait;
use chrono::Utc;
use sea_orm::{ActiveModelTrait, ColumnTrait, DatabaseConnection, EntityTrait, QueryFilter, Set};
use uuid::Uuid;

use crate::domain::auth::{
    model::Login,
    repository::{LoginRepository, LoginRepositoryError},
};
use crate::infrastructure::database::entity::{
    login, login::Entity as LoginEntity, session, session::Entity as SessionEntity, user,
    user::Entity as UserEntity,
};

fn to_domain(m: login::Model, user_oid: Uuid) -> Login {
    Login {
        oid: m.oid,
        user_oid,
        status: m.status,
        failed_attempts: m.failed_attempts,
        created_at: chrono::DateTime::<Utc>::from(m.created_at),
        acr: m.acr,
        requested_acr: m.requested_acr,
    }
}

pub struct LoginRepositoryImpl {
    db: DatabaseConnection,
}

impl LoginRepositoryImpl {
    pub fn new(db: DatabaseConnection) -> Self {
        Self { db }
    }
}

#[async_trait]
impl LoginRepository for LoginRepositoryImpl {
    async fn find_by_oid(&self, oid: Uuid) -> Result<Option<Login>, LoginRepositoryError> {
        // JOIN login → user so we can populate Login::user_oid without a
        // second round-trip.
        let row = LoginEntity::find()
            .filter(login::Column::Oid.eq(oid))
            .find_also_related(UserEntity)
            .one(&self.db)
            .await
            .map_err(LoginRepositoryError::QueryFailed)?;

        Ok(row.and_then(|(login_model, user_model)| {
            let user_oid = user_model?.oid;
            Some(to_domain(login_model, user_oid))
        }))
    }

    async fn create(
        &self,
        user_oid: Uuid,
        status: &str,
        requested_acr: Option<&str>,
    ) -> Result<Login, LoginRepositoryError> {
        // Resolve user OID → internal user.id (kept as a DB-layer concern).
        let user = UserEntity::find()
            .filter(user::Column::Oid.eq(user_oid))
            .one(&self.db)
            .await
            .map_err(LoginRepositoryError::QueryFailed)?
            .ok_or(LoginRepositoryError::UserNotFound)?;

        let now = Utc::now();
        let active = login::ActiveModel {
            oid: Set(Uuid::new_v4()),
            user_id: Set(Some(user.id)),
            status: Set(status.to_owned()),
            failed_attempts: Set(0),
            requested_acr: Set(requested_acr.map(str::to_owned)),
            created_at: Set(now.into()),
            ..Default::default()
        };
        let model = active
            .insert(&self.db)
            .await
            .map_err(LoginRepositoryError::CreateFailed)?;
        Ok(to_domain(model, user_oid))
    }

    async fn update_status(
        &self,
        login_oid: Uuid,
        status: &str,
        session_oid: Option<Uuid>,
        acr: Option<&str>,
    ) -> Result<(), LoginRepositoryError> {
        let model = LoginEntity::find()
            .filter(login::Column::Oid.eq(login_oid))
            .one(&self.db)
            .await
            .map_err(LoginRepositoryError::QueryFailed)?
            .ok_or(LoginRepositoryError::LoginNotFound)?;

        let session_id = if let Some(s_oid) = session_oid {
            let session = SessionEntity::find()
                .filter(session::Column::Oid.eq(s_oid))
                .one(&self.db)
                .await
                .map_err(LoginRepositoryError::QueryFailed)?
                .ok_or(LoginRepositoryError::SessionNotFound)?;
            Some(session.id)
        } else {
            None
        };

        let mut active: login::ActiveModel = model.into();
        active.status = Set(status.to_owned());
        if let Some(sid) = session_id {
            active.session_id = Set(Some(sid));
        }
        if let Some(a) = acr {
            active.acr = Set(Some(a.to_owned()));
        }
        active.updated_at = Set(Some(Utc::now().into()));
        active
            .update(&self.db)
            .await
            .map_err(LoginRepositoryError::UpdateFailed)?;
        Ok(())
    }

    async fn increment_failed_attempts(
        &self,
        login_oid: Uuid,
        failure_reason: Option<&str>,
    ) -> Result<(), LoginRepositoryError> {
        let model = LoginEntity::find()
            .filter(login::Column::Oid.eq(login_oid))
            .one(&self.db)
            .await
            .map_err(LoginRepositoryError::QueryFailed)?
            .ok_or(LoginRepositoryError::LoginNotFound)?;

        let new_attempts = model.failed_attempts + 1;
        let mut active: login::ActiveModel = model.into();
        active.failed_attempts = Set(new_attempts);
        if let Some(reason) = failure_reason {
            active.failure_reason = Set(Some(reason.to_owned()));
        }
        active.updated_at = Set(Some(Utc::now().into()));
        active
            .update(&self.db)
            .await
            .map_err(LoginRepositoryError::IncrementFailedAttempts)?;
        Ok(())
    }
}
