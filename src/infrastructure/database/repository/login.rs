use async_trait::async_trait;
use chrono::Utc;
use sea_orm::{
    ActiveModelTrait, ColumnTrait, DatabaseConnection, EntityTrait, ExprTrait, QueryFilter, Set,
    sea_query::Expr,
};
use uuid::Uuid;

use crate::database::entity::{
    client, client::Entity as ClientEntity, client_authorization,
    client_authorization::Entity as ClientAuthorizationEntity, login, login::Entity as LoginEntity,
    session, session::Entity as SessionEntity, user, user::Entity as UserEntity,
};
use identity_domain::auth::{
    model::Login,
    repository::{LoginRepository, LoginRepositoryError},
};

fn to_domain(
    m: login::Model,
    client_oid: Uuid,
    client_authorization_oid: Uuid,
    user_oid: Option<Uuid>,
) -> Login {
    Login {
        oid: m.oid,
        client_oid,
        client_authorization_oid,
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
        let Some(model) = LoginEntity::find()
            .filter(login::Column::Oid.eq(oid))
            .one(&self.db)
            .await
            .map_err(LoginRepositoryError::QueryFailed)?
        else {
            return Ok(None);
        };

        let client_model = ClientEntity::find_by_id(model.client_id)
            .one(&self.db)
            .await
            .map_err(LoginRepositoryError::QueryFailed)?
            .ok_or(LoginRepositoryError::UserNotFound)?;

        let client_authorization_model =
            ClientAuthorizationEntity::find_by_id(model.client_authorization_id)
                .one(&self.db)
                .await
                .map_err(LoginRepositoryError::QueryFailed)?
                .ok_or(LoginRepositoryError::LoginNotFound)?;

        let user_oid = match model.user_id {
            Some(user_id) => UserEntity::find_by_id(user_id)
                .one(&self.db)
                .await
                .map_err(LoginRepositoryError::QueryFailed)?
                .map(|user| user.oid),
            None => None,
        };

        Ok(Some(to_domain(
            model,
            client_model.oid,
            client_authorization_model.oid,
            user_oid,
        )))
    }

    async fn create_pending(
        &self,
        client_oid: Uuid,
        client_authorization_oid: Uuid,
        requested_acr: Option<&str>,
    ) -> Result<Login, LoginRepositoryError> {
        let client = ClientEntity::find()
            .filter(client::Column::Oid.eq(client_oid))
            .one(&self.db)
            .await
            .map_err(LoginRepositoryError::QueryFailed)?
            .ok_or(LoginRepositoryError::UserNotFound)?;

        let client_authorization_model = ClientAuthorizationEntity::find()
            .filter(client_authorization::Column::Oid.eq(client_authorization_oid))
            .one(&self.db)
            .await
            .map_err(LoginRepositoryError::QueryFailed)?
            .ok_or(LoginRepositoryError::UserNotFound)?;

        let now = Utc::now();
        let active = login::ActiveModel {
            oid: Set(Uuid::new_v4()),
            client_id: Set(client.id),
            client_authorization_id: Set(client_authorization_model.id),
            user_id: Set(None),
            status: Set(identity_domain::auth::LoginStatus::CREATED.to_owned()),
            failed_attempts: Set(0),
            requested_acr: Set(requested_acr.map(str::to_owned)),
            created_at: Set(now.into()),
            ..Default::default()
        };
        let model = active
            .insert(&self.db)
            .await
            .map_err(LoginRepositoryError::CreateFailed)?;
        Ok(to_domain(model, client_oid, client_authorization_oid, None))
    }

    async fn bind_user(
        &self,
        login_oid: Uuid,
        user_oid: Uuid,
        status: &str,
    ) -> Result<Login, LoginRepositoryError> {
        let user = UserEntity::find()
            .filter(user::Column::Oid.eq(user_oid))
            .one(&self.db)
            .await
            .map_err(LoginRepositoryError::QueryFailed)?
            .ok_or(LoginRepositoryError::UserNotFound)?;

        let model = LoginEntity::find()
            .filter(login::Column::Oid.eq(login_oid))
            .one(&self.db)
            .await
            .map_err(LoginRepositoryError::QueryFailed)?
            .ok_or(LoginRepositoryError::LoginNotFound)?;

        let mut active: login::ActiveModel = model.into();
        active.user_id = Set(Some(user.id));
        active.status = Set(status.to_owned());
        active.updated_at = Set(Some(Utc::now().into()));

        let model = active
            .update(&self.db)
            .await
            .map_err(LoginRepositoryError::UpdateFailed)?;

        let client_model = ClientEntity::find_by_id(model.client_id)
            .one(&self.db)
            .await
            .map_err(LoginRepositoryError::QueryFailed)?
            .ok_or(LoginRepositoryError::UserNotFound)?;

        let client_authorization_model =
            ClientAuthorizationEntity::find_by_id(model.client_authorization_id)
                .one(&self.db)
                .await
                .map_err(LoginRepositoryError::QueryFailed)?
                .ok_or(LoginRepositoryError::LoginNotFound)?;

        Ok(to_domain(
            model,
            client_model.oid,
            client_authorization_model.oid,
            Some(user_oid),
        ))
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
        let now = Utc::now().naive_utc();
        let mut update = LoginEntity::update_many()
            .col_expr(
                login::Column::FailedAttempts,
                Expr::col(login::Column::FailedAttempts).add(1),
            )
            .col_expr(
                login::Column::UpdatedAt,
                Expr::value(Option::<chrono::NaiveDateTime>::Some(now)),
            )
            .filter(login::Column::Oid.eq(login_oid));

        if let Some(reason) = failure_reason {
            update = update.col_expr(
                login::Column::FailureReason,
                Expr::value(Option::<String>::Some(reason.to_owned())),
            );
        }

        update
            .exec(&self.db)
            .await
            .map_err(LoginRepositoryError::IncrementFailedAttempts)?;
        Ok(())
    }
}
