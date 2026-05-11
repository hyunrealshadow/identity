use async_trait::async_trait;
use chrono::Utc;
use sea_orm::{
    ActiveModelTrait, ColumnTrait, Condition, DatabaseConnection, EntityTrait, QueryFilter, Set,
    sea_query::{Expr, SimpleExpr},
};
use uuid::Uuid;

use crate::database::entity::{
    client, client::Entity as ClientEntity, client_authorization,
    client_authorization::Entity as ClientAuthorizationEntity,
};
use identity_domain::{
    auth::SessionOid,
    client::model::ClientOid,
    client_authorization::{
        ClientAuthorization, ClientAuthorizationRepository, ClientAuthorizationRepositoryError,
        ClientAuthorizationType, ConsentState, SelectionSource, StoredAuthorizationRequest,
    },
    openid_connect::AuthorizationRequestData,
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
            ClientAuthorizationRepositoryError::QueryFailed(sea_orm::DbErr::Type(
                "invalid authorization_request payload".into(),
            ))
        })
}

fn can_overwrite_selection(current: Option<SelectionSource>, next: SelectionSource) -> bool {
    match (current, next) {
        (Some(SelectionSource::FreshLogin), SelectionSource::AccountPicker) => false,
        (Some(existing), incoming) if existing == incoming => true,
        (Some(SelectionSource::Auto), SelectionSource::AccountPicker) => true,
        (Some(SelectionSource::Auto), SelectionSource::FreshLogin) => true,
        (None, _) => true,
        _ => true,
    }
}

fn selection_update_condition(model: &client_authorization::Model) -> Condition {
    let mut condition = Condition::all()
        .add(client_authorization::Column::Oid.eq(model.oid))
        .add(client_authorization::Column::CompletedAt.is_null());

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
    Ok(ClientAuthorization {
        oid: model.oid,
        client_oid,
        type_: model
            .r#type
            .parse::<ClientAuthorizationType>()
            .map_err(|_| {
                ClientAuthorizationRepositoryError::QueryFailed(sea_orm::DbErr::Type(
                    "invalid client_authorization.type".into(),
                ))
            })?,
        data: model.data,
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
        type_: ClientAuthorizationType,
        data: serde_json::Value,
        expires_at: chrono::DateTime<Utc>,
    ) -> Result<ClientAuthorization, ClientAuthorizationRepositoryError> {
        let client_model = ClientEntity::find()
            .filter(client::Column::Oid.eq(client_oid))
            .one(&self.db)
            .await
            .map_err(ClientAuthorizationRepositoryError::QueryFailed)?
            .ok_or_else(|| {
                ClientAuthorizationRepositoryError::QueryFailed(sea_orm::DbErr::RecordNotFound(
                    format!("client {client_oid} not found"),
                ))
            })?;

        let now = Utc::now();
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
        .insert(&self.db)
        .await
        .map_err(ClientAuthorizationRepositoryError::QueryFailed)?;

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
            .map_err(ClientAuthorizationRepositoryError::QueryFailed)?
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
            .map_err(ClientAuthorizationRepositoryError::QueryFailed)?
        else {
            return Ok(false);
        };

        if model.r#type != ClientAuthorizationType::AuthorizationRequest.to_string()
            || model.completed_at.is_some()
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
        let result = ClientAuthorizationEntity::update_many()
            .col_expr(
                client_authorization::Column::Data,
                SimpleExpr::Value(serde_json::to_value(stored).unwrap().into()),
            )
            .col_expr(
                client_authorization::Column::UpdatedAt,
                SimpleExpr::Value(Some(now).into()),
            )
            .filter(selection_update_condition(&model))
            .exec(&self.db)
            .await
            .map_err(ClientAuthorizationRepositoryError::QueryFailed)?;

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
            .map_err(ClientAuthorizationRepositoryError::QueryFailed)?
        else {
            return Ok(false);
        };

        if model.r#type != ClientAuthorizationType::AuthorizationRequest.to_string()
            || model.completed_at.is_some()
        {
            return Ok(false);
        }

        let mut stored = parse_stored_authorization_request(model.data.clone())?;
        if stored.interaction.consent_state != ConsentState::Pending {
            return Ok(false);
        }

        stored.interaction.consent_state = consent_state;
        stored.interaction.consent_decided_at = Some(decided_at.to_rfc3339());

        let now = Utc::now();
        let result = ClientAuthorizationEntity::update_many()
            .col_expr(
                client_authorization::Column::Data,
                SimpleExpr::Value(serde_json::to_value(stored).unwrap().into()),
            )
            .col_expr(
                client_authorization::Column::UpdatedAt,
                SimpleExpr::Value(Some(now).into()),
            )
            .filter(selection_update_condition(&model))
            .exec(&self.db)
            .await
            .map_err(ClientAuthorizationRepositoryError::QueryFailed)?;

        Ok(result.rows_affected == 1)
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
                    .add(client_authorization::Column::CompletedAt.is_null()),
            )
            .exec(&self.db)
            .await
            .map_err(ClientAuthorizationRepositoryError::QueryFailed)?;

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
            .map_err(ClientAuthorizationRepositoryError::QueryFailed)?;

        Ok(())
    }

    async fn revoke(&self, oid: Uuid) -> Result<(), ClientAuthorizationRepositoryError> {
        let Some(model) = ClientAuthorizationEntity::find()
            .filter(client_authorization::Column::Oid.eq(oid))
            .one(&self.db)
            .await
            .map_err(ClientAuthorizationRepositoryError::QueryFailed)?
        else {
            return Ok(());
        };

        let mut active: client_authorization::ActiveModel = model.into();
        active.revoked_at = Set(Some(Utc::now().into()));
        active.updated_at = Set(Some(Utc::now().into()));
        active
            .update(&self.db)
            .await
            .map_err(ClientAuthorizationRepositoryError::QueryFailed)?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::ClientAuthorizationRepositoryImpl;

    #[test]
    fn client_authorization_repo_impl_exists() {
        let _ = ClientAuthorizationRepositoryImpl::new;
    }
}
