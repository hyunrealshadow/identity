use async_trait::async_trait;
use chrono::Utc;
use sea_orm::{
    ActiveModelTrait, ColumnTrait, Condition, DatabaseConnection, EntityTrait, QueryFilter,
    QuerySelect, Set, TransactionTrait,
    sea_query::{Expr, OnConflict, SimpleExpr},
};
use uuid::Uuid;

use crate::database::entity::{
    client, client::Entity as ClientEntity, client_authorization,
    client_authorization::Entity as ClientAuthorizationEntity, scope, scope::Entity as ScopeEntity,
    session, session::Entity as SessionEntity, user, user::Entity as UserEntity,
    user_client_consent, user_client_consent::Entity as UserClientConsentEntity,
};
use crate::database::repository::shared::lock_session;
use identity_domain::{
    auth::SessionOid,
    client::model::ClientOid,
    client_authorization::{
        AccessTokenData, AuthorizationCodeData, ClientAuthorization, ClientAuthorizationData,
        ClientAuthorizationRepository, ClientAuthorizationRepositoryError, ClientAuthorizationType,
        ConsentState, RefreshTokenData, RegistrationAccessTokenData, SelectionSource,
        StoredAuthorizationRequest,
    },
    openid_connect::{AuthorizationRequestData, ScopeSet},
};

fn parse_stored_authorization_request(
    data: serde_json::Value,
) -> Result<StoredAuthorizationRequest, ClientAuthorizationRepositoryError> {
    serde_json::from_value::<StoredAuthorizationRequest>(data.clone())
        .or_else(|_| {
            serde_json::from_value::<AuthorizationRequestData>(data).map(|request| {
                StoredAuthorizationRequest {
                    request,
                    interaction: Default::default(),
                }
            })
        })
        .map_err(|_| {
            ClientAuthorizationRepositoryError::QueryFailed(Box::new(sea_orm::DbErr::Type(
                "invalid authorization_request payload".into(),
            )))
        })
}

fn serialize_data(
    data: &ClientAuthorizationData,
) -> Result<serde_json::Value, ClientAuthorizationRepositoryError> {
    match data {
        ClientAuthorizationData::AuthorizationRequest(value) => serde_json::to_value(value),
        ClientAuthorizationData::AuthorizationCode(value) => serde_json::to_value(value),
        ClientAuthorizationData::AccessToken(value) => serde_json::to_value(value),
        ClientAuthorizationData::RefreshToken(value) => serde_json::to_value(value),
        ClientAuthorizationData::RegistrationAccessToken(value) => serde_json::to_value(value),
    }
    .map_err(|error| ClientAuthorizationRepositoryError::QueryFailed(Box::new(error)))
}

fn scope_ids_cover(mut granted: Vec<i64>, mut requested: Vec<i64>) -> bool {
    granted.sort_unstable();
    granted.dedup();
    requested.sort_unstable();
    requested.dedup();

    requested
        .iter()
        .all(|scope_id| granted.binary_search(scope_id).is_ok())
}

fn parse_data(
    type_: &ClientAuthorizationType,
    data: serde_json::Value,
) -> Result<ClientAuthorizationData, ClientAuthorizationRepositoryError> {
    match type_ {
        ClientAuthorizationType::AuthorizationRequest => parse_stored_authorization_request(data)
            .map(ClientAuthorizationData::AuthorizationRequest),
        ClientAuthorizationType::AuthorizationCode => {
            serde_json::from_value::<AuthorizationCodeData>(data)
                .map(ClientAuthorizationData::AuthorizationCode)
                .map_err(|error| ClientAuthorizationRepositoryError::QueryFailed(Box::new(error)))
        }
        ClientAuthorizationType::AccessToken => serde_json::from_value::<AccessTokenData>(data)
            .map(ClientAuthorizationData::AccessToken)
            .map_err(|error| ClientAuthorizationRepositoryError::QueryFailed(Box::new(error))),
        ClientAuthorizationType::RefreshToken => serde_json::from_value::<RefreshTokenData>(data)
            .map(ClientAuthorizationData::RefreshToken)
            .map_err(|error| ClientAuthorizationRepositoryError::QueryFailed(Box::new(error))),
        ClientAuthorizationType::RegistrationAccessToken => {
            serde_json::from_value::<RegistrationAccessTokenData>(data)
                .map(ClientAuthorizationData::RegistrationAccessToken)
                .map_err(|error| ClientAuthorizationRepositoryError::QueryFailed(Box::new(error)))
        }
    }
}

fn can_overwrite_selection(current: Option<SelectionSource>, next: SelectionSource) -> bool {
    match (current, next) {
        (Some(SelectionSource::FreshLogin), SelectionSource::AccountPicker) => false,
        (Some(existing), incoming) if existing == incoming => true,
        (Some(SelectionSource::Reauthentication), _) => false,
        (Some(SelectionSource::Auto), SelectionSource::AccountPicker) => true,
        (Some(SelectionSource::Auto), SelectionSource::FreshLogin) => true,
        (None, _) => true,
        _ => true,
    }
}

fn selection_update_condition(
    model: &client_authorization::Model,
    now: chrono::DateTime<Utc>,
) -> Condition {
    let mut condition = Condition::all()
        .add(client_authorization::Column::Oid.eq(model.oid))
        .add(
            client_authorization::Column::Type
                .eq(ClientAuthorizationType::AuthorizationRequest.to_string()),
        )
        .add(client_authorization::Column::CompletedAt.is_null())
        .add(client_authorization::Column::RevokedAt.is_null())
        .add(client_authorization::Column::ExpiresAt.gt(now));

    condition = if let Some(updated_at) = model.updated_at {
        condition.add(client_authorization::Column::UpdatedAt.eq(updated_at))
    } else {
        condition.add(client_authorization::Column::UpdatedAt.is_null())
    };

    condition
}

fn to_domain(
    model: client_authorization::Model,
    client_oid: ClientOid,
) -> Result<ClientAuthorization, ClientAuthorizationRepositoryError> {
    let type_ = model
        .r#type
        .parse::<ClientAuthorizationType>()
        .map_err(|_| {
            ClientAuthorizationRepositoryError::QueryFailed(Box::new(sea_orm::DbErr::Type(
                "invalid client_authorization.type".into(),
            )))
        })?;
    let data = parse_data(&type_, model.data)?;

    Ok(ClientAuthorization {
        oid: model.oid,
        client_oid,
        type_,
        data,
        expires_at: model.expires_at.with_timezone(&Utc),
        completed_at: model.completed_at.map(|value| value.with_timezone(&Utc)),
        revoked_at: model.revoked_at.map(|value| value.with_timezone(&Utc)),
        created_at: model.created_at.with_timezone(&Utc),
        updated_at: model.updated_at.map(|value| value.with_timezone(&Utc)),
    })
}

pub struct ClientAuthorizationRepositoryImpl {
    db: DatabaseConnection,
}

impl ClientAuthorizationRepositoryImpl {
    pub fn new(db: DatabaseConnection) -> Self {
        Self { db }
    }
}

#[async_trait]
impl ClientAuthorizationRepository for ClientAuthorizationRepositoryImpl {
    async fn create(
        &self,
        client_oid: ClientOid,
        data: ClientAuthorizationData,
        expires_at: chrono::DateTime<Utc>,
    ) -> Result<ClientAuthorization, ClientAuthorizationRepositoryError> {
        let type_ = data.authorization_type();
        let session_oid = match &data {
            ClientAuthorizationData::AuthorizationCode(data) => Some(data.session_oid),
            ClientAuthorizationData::AccessToken(data) => Some(data.session_oid),
            ClientAuthorizationData::RefreshToken(data) => Some(data.session_oid),
            _ => None,
        };
        let transaction =
            self.db.begin().await.map_err(|error| {
                ClientAuthorizationRepositoryError::QueryFailed(Box::new(error))
            })?;
        if let Some(session_oid) = session_oid {
            lock_session(&transaction, session_oid)
                .await
                .map_err(|error| {
                    ClientAuthorizationRepositoryError::QueryFailed(Box::new(error))
                })?;
            let now = Utc::now();
            let session_available = SessionEntity::find()
                .filter(session::Column::Oid.eq(Uuid::from(session_oid)))
                .filter(
                    session::Column::Status
                        .eq(identity_domain::auth::SessionStatus::ACTIVE.as_str()),
                )
                .filter(session::Column::RevokedAt.is_null())
                .filter(session::Column::ExpiresAt.gt(now))
                .one(&transaction)
                .await
                .map_err(|error| ClientAuthorizationRepositoryError::QueryFailed(Box::new(error)))?
                .is_some();
            if !session_available {
                return Err(ClientAuthorizationRepositoryError::QueryFailed(Box::new(
                    sea_orm::DbErr::RecordNotFound(format!(
                        "session {} is not active",
                        Uuid::from(session_oid)
                    )),
                )));
            }
        }
        let client_model = ClientEntity::find()
            .filter(client::Column::Oid.eq(client_oid))
            .one(&transaction)
            .await
            .map_err(|e| ClientAuthorizationRepositoryError::QueryFailed(Box::new(e)))?
            .ok_or_else(|| {
                ClientAuthorizationRepositoryError::QueryFailed(Box::new(
                    sea_orm::DbErr::RecordNotFound(format!("client {client_oid} not found")),
                ))
            })?;

        let now = Utc::now();
        let data = serialize_data(&data)?;
        let model = client_authorization::ActiveModel {
            id: Default::default(),
            oid: Set(Uuid::new_v4()),
            client_id: Set(client_model.id),
            r#type: Set(type_.to_string()),
            data: Set(data),
            expires_at: Set(expires_at.into()),
            completed_at: Set(None),
            revoked_at: Set(None),
            created_at: Set(now.into()),
            updated_at: Set(Some(now.into())),
        }
        .insert(&transaction)
        .await
        .map_err(|e| ClientAuthorizationRepositoryError::QueryFailed(Box::new(e)))?;
        transaction
            .commit()
            .await
            .map_err(|error| ClientAuthorizationRepositoryError::QueryFailed(Box::new(error)))?;
        to_domain(model, client_oid)
    }

    async fn find_by_oid(
        &self,
        oid: Uuid,
    ) -> Result<Option<ClientAuthorization>, ClientAuthorizationRepositoryError> {
        let Some((request_model, Some(client_model))) = ClientAuthorizationEntity::find()
            .filter(client_authorization::Column::Oid.eq(oid))
            .inner_join(ClientEntity)
            .select_also(ClientEntity)
            .one(&self.db)
            .await
            .map_err(|e| ClientAuthorizationRepositoryError::QueryFailed(Box::new(e)))?
        else {
            return Ok(None);
        };

        Ok(Some(to_domain(request_model, client_model.oid)?))
    }

    async fn update_authorization_request_selection(
        &self,
        oid: Uuid,
        session_oid: SessionOid,
        user_oid: Uuid,
        protected_session_id: Option<String>,
        source: SelectionSource,
    ) -> Result<bool, ClientAuthorizationRepositoryError> {
        let Some(model) = ClientAuthorizationEntity::find()
            .filter(client_authorization::Column::Oid.eq(oid))
            .one(&self.db)
            .await
            .map_err(|e| ClientAuthorizationRepositoryError::QueryFailed(Box::new(e)))?
        else {
            return Ok(false);
        };

        if model.r#type != ClientAuthorizationType::AuthorizationRequest.to_string()
            || model.completed_at.is_some()
            || model.revoked_at.is_some()
            || model.expires_at.with_timezone(&Utc) <= Utc::now()
        {
            return Ok(false);
        }

        let mut stored = parse_stored_authorization_request(model.data.clone())?;
        if !can_overwrite_selection(stored.interaction.selection_source, source) {
            return Ok(false);
        }

        stored.interaction.selected_session_oid = Some(session_oid);
        stored.interaction.selected_protected_session_id = protected_session_id;
        stored.interaction.selected_user_oid = Some(user_oid.to_string());
        stored.interaction.selection_source = Some(source);

        let now = Utc::now();
        let stored_data = serde_json::to_value(stored)
            .map_err(|e| ClientAuthorizationRepositoryError::QueryFailed(Box::new(e)))?;
        let result = ClientAuthorizationEntity::update_many()
            .col_expr(
                client_authorization::Column::Data,
                SimpleExpr::Value(stored_data.into()),
            )
            .col_expr(
                client_authorization::Column::UpdatedAt,
                SimpleExpr::Value(Some(now).into()),
            )
            .filter(selection_update_condition(&model, now))
            .exec(&self.db)
            .await
            .map_err(|e| ClientAuthorizationRepositoryError::QueryFailed(Box::new(e)))?;

        Ok(result.rows_affected == 1)
    }

    async fn record_authorization_request_consent(
        &self,
        oid: Uuid,
        consent_state: ConsentState,
        decided_at: chrono::DateTime<Utc>,
    ) -> Result<bool, ClientAuthorizationRepositoryError> {
        let Some(model) = ClientAuthorizationEntity::find()
            .filter(client_authorization::Column::Oid.eq(oid))
            .one(&self.db)
            .await
            .map_err(|e| ClientAuthorizationRepositoryError::QueryFailed(Box::new(e)))?
        else {
            return Ok(false);
        };

        if model.r#type != ClientAuthorizationType::AuthorizationRequest.to_string()
            || model.completed_at.is_some()
            || model.revoked_at.is_some()
            || model.expires_at.with_timezone(&Utc) <= Utc::now()
        {
            return Ok(false);
        }

        let mut stored = parse_stored_authorization_request(model.data.clone())?;
        if stored.interaction.consent_state != ConsentState::Pending {
            return Ok(false);
        }

        let grant = if consent_state == ConsentState::Approved {
            let user_oid = stored
                .interaction
                .selected_user_oid
                .as_deref()
                .ok_or_else(|| {
                    ClientAuthorizationRepositoryError::QueryFailed(Box::new(sea_orm::DbErr::Type(
                        "approved consent has no selected user".into(),
                    )))
                })?
                .parse::<Uuid>()
                .map_err(|error| {
                    ClientAuthorizationRepositoryError::QueryFailed(Box::new(error))
                })?;
            let scope = ScopeSet::parse(&stored.request.scope).map_err(|error| {
                ClientAuthorizationRepositoryError::QueryFailed(Box::new(error))
            })?;
            Some((user_oid, scope))
        } else {
            None
        };

        stored.interaction.consent_state = consent_state;
        stored.interaction.consent_decided_at = Some(decided_at.to_rfc3339());

        let now = Utc::now();
        let stored_data = serde_json::to_value(stored)
            .map_err(|e| ClientAuthorizationRepositoryError::QueryFailed(Box::new(e)))?;
        let transaction =
            self.db.begin().await.map_err(|error| {
                ClientAuthorizationRepositoryError::QueryFailed(Box::new(error))
            })?;
        let result = ClientAuthorizationEntity::update_many()
            .col_expr(
                client_authorization::Column::Data,
                SimpleExpr::Value(stored_data.into()),
            )
            .col_expr(
                client_authorization::Column::UpdatedAt,
                SimpleExpr::Value(Some(now).into()),
            )
            .filter(selection_update_condition(&model, now))
            .exec(&transaction)
            .await
            .map_err(|e| ClientAuthorizationRepositoryError::QueryFailed(Box::new(e)))?;

        if result.rows_affected != 1 {
            return Ok(false);
        }

        if let Some((user_oid, requested_scope)) = grant {
            let user_id = UserEntity::find()
                .select_only()
                .column(user::Column::Id)
                .filter(user::Column::Oid.eq(user_oid))
                .into_tuple::<i64>()
                .one(&transaction)
                .await
                .map_err(|error| ClientAuthorizationRepositoryError::QueryFailed(Box::new(error)))?
                .ok_or_else(|| {
                    ClientAuthorizationRepositoryError::QueryFailed(Box::new(
                        sea_orm::DbErr::RecordNotFound(format!("user {user_oid} not found")),
                    ))
                })?;
            let requested_scope_names = requested_scope.names();
            let mut scope_ids = ScopeEntity::find()
                .select_only()
                .column(scope::Column::Id)
                .filter(scope::Column::Protocol.eq("openid_connect"))
                .filter(scope::Column::Name.is_in(requested_scope_names.iter().copied()))
                .into_tuple::<i64>()
                .all(&transaction)
                .await
                .map_err(|error| {
                    ClientAuthorizationRepositoryError::QueryFailed(Box::new(error))
                })?;
            scope_ids.sort_unstable();
            scope_ids.dedup();
            if scope_ids.len() != requested_scope_names.len() {
                return Err(ClientAuthorizationRepositoryError::QueryFailed(Box::new(
                    sea_orm::DbErr::RecordNotFound(
                        "one or more consent scopes were not found".to_owned(),
                    ),
                )));
            }
            let grants = scope_ids
                .into_iter()
                .map(|scope_id| user_client_consent::ActiveModel {
                    scope_id: Set(scope_id),
                    user_id: Set(user_id),
                    client_id: Set(model.client_id),
                    approved_at: Set(decided_at.into()),
                    ..Default::default()
                });
            UserClientConsentEntity::insert_many(grants)
                .on_conflict(
                    OnConflict::columns([
                        user_client_consent::Column::UserId,
                        user_client_consent::Column::ClientId,
                        user_client_consent::Column::ScopeId,
                    ])
                    .update_column(user_client_consent::Column::ApprovedAt)
                    .to_owned(),
                )
                .exec(&transaction)
                .await
                .map_err(|error| {
                    ClientAuthorizationRepositoryError::QueryFailed(Box::new(error))
                })?;
        }

        transaction
            .commit()
            .await
            .map_err(|error| ClientAuthorizationRepositoryError::QueryFailed(Box::new(error)))?;
        Ok(true)
    }

    async fn has_user_consent(
        &self,
        user_oid: Uuid,
        client_oid: ClientOid,
        requested_scope: &ScopeSet,
    ) -> Result<bool, ClientAuthorizationRepositoryError> {
        let Some(user) = UserEntity::find()
            .filter(user::Column::Oid.eq(user_oid))
            .one(&self.db)
            .await
            .map_err(|error| ClientAuthorizationRepositoryError::QueryFailed(Box::new(error)))?
        else {
            return Ok(false);
        };
        let Some(client) = ClientEntity::find()
            .filter(client::Column::Oid.eq(Uuid::from(client_oid)))
            .one(&self.db)
            .await
            .map_err(|error| ClientAuthorizationRepositoryError::QueryFailed(Box::new(error)))?
        else {
            return Ok(false);
        };
        let requested_scope_names = requested_scope.names();
        let mut requested_scope_ids = ScopeEntity::find()
            .select_only()
            .column(scope::Column::Id)
            .filter(scope::Column::Protocol.eq("openid_connect"))
            .filter(scope::Column::Name.is_in(requested_scope_names.iter().copied()))
            .into_tuple::<i64>()
            .all(&self.db)
            .await
            .map_err(|error| ClientAuthorizationRepositoryError::QueryFailed(Box::new(error)))?;
        requested_scope_ids.sort_unstable();
        requested_scope_ids.dedup();
        if requested_scope_ids.len() != requested_scope_names.len() {
            return Ok(false);
        }

        let granted_scope_ids = UserClientConsentEntity::find()
            .select_only()
            .column(user_client_consent::Column::ScopeId)
            .filter(user_client_consent::Column::UserId.eq(user.id))
            .filter(user_client_consent::Column::ClientId.eq(client.id))
            .into_tuple::<i64>()
            .all(&self.db)
            .await
            .map_err(|error| ClientAuthorizationRepositoryError::QueryFailed(Box::new(error)))?;
        Ok(scope_ids_cover(granted_scope_ids, requested_scope_ids))
    }

    async fn mark_authorization_request_completed(
        &self,
        oid: Uuid,
        completed_at: chrono::DateTime<Utc>,
    ) -> Result<bool, ClientAuthorizationRepositoryError> {
        let now = Utc::now();
        let result = ClientAuthorizationEntity::update_many()
            .col_expr(
                client_authorization::Column::CompletedAt,
                SimpleExpr::Value(Some(completed_at).into()),
            )
            .col_expr(
                client_authorization::Column::UpdatedAt,
                SimpleExpr::Value(Some(now).into()),
            )
            .filter(
                Condition::all()
                    .add(client_authorization::Column::Oid.eq(oid))
                    .add(
                        client_authorization::Column::Type
                            .eq(ClientAuthorizationType::AuthorizationRequest.to_string()),
                    )
                    .add(client_authorization::Column::CompletedAt.is_null())
                    .add(client_authorization::Column::RevokedAt.is_null())
                    .add(client_authorization::Column::ExpiresAt.gt(now)),
            )
            .exec(&self.db)
            .await
            .map_err(|e| ClientAuthorizationRepositoryError::QueryFailed(Box::new(e)))?;

        Ok(result.rows_affected == 1)
    }

    async fn revoke_access_tokens_for_authorization_code(
        &self,
        authorization_code_oid: Uuid,
    ) -> Result<(), ClientAuthorizationRepositoryError> {
        let now = Utc::now();
        ClientAuthorizationEntity::update_many()
            .col_expr(
                client_authorization::Column::RevokedAt,
                SimpleExpr::Value(now.into()),
            )
            .col_expr(
                client_authorization::Column::UpdatedAt,
                SimpleExpr::Value(now.into()),
            )
            .filter(
                Condition::all()
                    .add(
                        client_authorization::Column::Type
                            .eq(ClientAuthorizationType::AccessToken.to_string()),
                    )
                    .add(client_authorization::Column::RevokedAt.is_null())
                    .add(Expr::cust_with_values(
                        r#"("client_authorization"."data"->>'authorization_code_oid') = $1"#,
                        [authorization_code_oid.to_string()],
                    )),
            )
            .exec(&self.db)
            .await
            .map_err(|e| ClientAuthorizationRepositoryError::QueryFailed(Box::new(e)))?;

        Ok(())
    }

    async fn revoke_if_active(
        &self,
        oid: Uuid,
        type_: ClientAuthorizationType,
        now: chrono::DateTime<Utc>,
    ) -> Result<bool, ClientAuthorizationRepositoryError> {
        let result = ClientAuthorizationEntity::update_many()
            .col_expr(
                client_authorization::Column::RevokedAt,
                SimpleExpr::Value(Some(now).into()),
            )
            .col_expr(
                client_authorization::Column::UpdatedAt,
                SimpleExpr::Value(Some(now).into()),
            )
            .filter(
                Condition::all()
                    .add(client_authorization::Column::Oid.eq(oid))
                    .add(client_authorization::Column::Type.eq(type_.to_string()))
                    .add(client_authorization::Column::RevokedAt.is_null())
                    .add(client_authorization::Column::ExpiresAt.gt(now)),
            )
            .exec(&self.db)
            .await
            .map_err(|e| ClientAuthorizationRepositoryError::QueryFailed(Box::new(e)))?;

        Ok(result.rows_affected == 1)
    }
}

#[cfg(test)]
mod selection_tests {
    use super::{can_overwrite_selection, scope_ids_cover};
    use identity_domain::client_authorization::SelectionSource;

    #[test]
    fn reauthentication_cannot_be_replaced_by_another_selection_flow() {
        assert!(!can_overwrite_selection(
            Some(SelectionSource::Reauthentication),
            SelectionSource::AccountPicker,
        ));
        assert!(!can_overwrite_selection(
            Some(SelectionSource::Reauthentication),
            SelectionSource::FreshLogin,
        ));
        assert!(can_overwrite_selection(
            Some(SelectionSource::Reauthentication),
            SelectionSource::Reauthentication,
        ));
    }

    #[test]
    fn consent_scope_comparison_sorts_deduplicates_and_accepts_subsets() {
        assert!(scope_ids_cover(vec![3, 1, 2, 2], vec![2, 1, 1]));
        assert!(!scope_ids_cover(vec![3, 1, 1], vec![1, 2]));
    }
}
