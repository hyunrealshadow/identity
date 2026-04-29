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
    client::model::ClientOid,
    client_authorization::{
        ClientAuthorization, ClientAuthorizationRepository, ClientAuthorizationRepositoryError,
        ClientAuthorizationType,
    },
};

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
