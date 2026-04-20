use async_trait::async_trait;
use chrono::Utc;
use sea_orm::{
    ActiveModelTrait, ColumnTrait, Condition, DatabaseConnection, EntityTrait, QueryFilter, Set,
    sea_query::Expr,
};
use uuid::Uuid;

use crate::domain::{
    client::model::ClientOid,
    client_request::{
        ClientRequest, ClientRequestRepository, ClientRequestRepositoryError, ClientRequestType,
    },
};
use crate::infrastructure::database::entity::{
    client, client::Entity as ClientEntity, client_request,
    client_request::Entity as ClientRequestEntity,
};

fn to_domain(
    model: client_request::Model,
    client_oid: ClientOid,
) -> Result<ClientRequest, ClientRequestRepositoryError> {
    Ok(ClientRequest {
        oid: model.oid,
        client_oid,
        type_: model.r#type.parse::<ClientRequestType>().map_err(|_| {
            ClientRequestRepositoryError::QueryFailed(sea_orm::DbErr::Type(
                "invalid client_request.type".into(),
            ))
        })?,
        data: model.data,
        expires_at: model.expires_at.with_timezone(&Utc),
        revoked_at: model.revoked_at.map(|value| value.with_timezone(&Utc)),
        created_at: model.created_at.with_timezone(&Utc),
        updated_at: model.updated_at.map(|value| value.with_timezone(&Utc)),
    })
}

pub struct ClientRequestRepositoryImpl {
    db: DatabaseConnection,
}

impl ClientRequestRepositoryImpl {
    pub fn new(db: DatabaseConnection) -> Self {
        Self { db }
    }
}

#[async_trait]
impl ClientRequestRepository for ClientRequestRepositoryImpl {
    async fn create(
        &self,
        client_oid: ClientOid,
        type_: ClientRequestType,
        data: serde_json::Value,
        expires_at: chrono::DateTime<Utc>,
    ) -> Result<ClientRequest, ClientRequestRepositoryError> {
        let client_model = ClientEntity::find()
            .filter(client::Column::Oid.eq(client_oid))
            .one(&self.db)
            .await
            .map_err(ClientRequestRepositoryError::QueryFailed)?
            .ok_or_else(|| {
                ClientRequestRepositoryError::QueryFailed(sea_orm::DbErr::RecordNotFound(format!(
                    "client {client_oid} not found"
                )))
            })?;

        let now = Utc::now();
        let model = client_request::ActiveModel {
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
        .map_err(ClientRequestRepositoryError::QueryFailed)?;

        to_domain(model, client_oid)
    }

    async fn find_by_oid(
        &self,
        oid: Uuid,
    ) -> Result<Option<ClientRequest>, ClientRequestRepositoryError> {
        let Some((request_model, Some(client_model))) = ClientRequestEntity::find()
            .filter(client_request::Column::Oid.eq(oid))
            .inner_join(ClientEntity)
            .select_also(ClientEntity)
            .one(&self.db)
            .await
            .map_err(ClientRequestRepositoryError::QueryFailed)?
        else {
            return Ok(None);
        };

        Ok(Some(to_domain(request_model, client_model.oid)?))
    }

    async fn find_refresh_token_by_token(
        &self,
        token: &str,
    ) -> Result<Option<ClientRequest>, ClientRequestRepositoryError> {
        let Some((request_model, Some(client_model))) = ClientRequestEntity::find()
            .filter(
                Condition::all()
                    .add(
                        client_request::Column::Type
                            .eq(ClientRequestType::RefreshToken.to_string()),
                    )
                    .add(Expr::cust_with_values(
                        r#"("client_request"."data"->>'token') = $1"#,
                        [token],
                    )),
            )
            .inner_join(ClientEntity)
            .select_also(ClientEntity)
            .one(&self.db)
            .await
            .map_err(ClientRequestRepositoryError::QueryFailed)?
        else {
            return Ok(None);
        };

        Ok(Some(to_domain(request_model, client_model.oid)?))
    }

    async fn revoke(&self, oid: Uuid) -> Result<(), ClientRequestRepositoryError> {
        let Some(model) = ClientRequestEntity::find()
            .filter(client_request::Column::Oid.eq(oid))
            .one(&self.db)
            .await
            .map_err(ClientRequestRepositoryError::QueryFailed)?
        else {
            return Ok(());
        };

        let mut active: client_request::ActiveModel = model.into();
        active.revoked_at = Set(Some(Utc::now().into()));
        active.updated_at = Set(Some(Utc::now().into()));
        active
            .update(&self.db)
            .await
            .map_err(ClientRequestRepositoryError::QueryFailed)?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::ClientRequestRepositoryImpl;

    #[test]
    fn client_request_repo_impl_exists() {
        let _ = ClientRequestRepositoryImpl::new;
    }
}
