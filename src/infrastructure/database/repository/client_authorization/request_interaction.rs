use super::mapping::parse_stored_authorization_request;
use super::query_error;
use crate::database::entity::{
    client_authorization, client_authorization::Entity as ClientAuthorizationEntity,
};
use chrono::{DateTime, Utc};
use identity_domain::{
    auth::SessionOid,
    client_authorization::{
        ClientAuthorizationRepositoryError, ClientAuthorizationType, SelectionSource,
    },
};
use sea_orm::{
    ColumnTrait, Condition, DatabaseConnection, EntityTrait, QueryFilter, sea_query::SimpleExpr,
};
use serde_json::to_value;
use uuid::Uuid;

pub(super) fn selection_update_condition(
    model: &client_authorization::Model,
    now: DateTime<Utc>,
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

#[tracing::instrument(skip_all, name = "db.query", fields(db.system = "postgresql", db.operation = "update_authorization_request_selection"))]
pub(super) async fn update_authorization_request_selection(
    db: &DatabaseConnection,
    oid: Uuid,
    session_oid: SessionOid,
    user_oid: Uuid,
    protected_session_id: Option<String>,
    source: SelectionSource,
) -> Result<bool, ClientAuthorizationRepositoryError> {
    let Some(model) = ClientAuthorizationEntity::find()
        .filter(client_authorization::Column::Oid.eq(oid))
        .one(db)
        .await
        .map_err(query_error(
            "client_authorization.update_authorization_request_selection",
        ))?
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
    if !source.can_replace(stored.interaction.selection_source) {
        return Ok(false);
    }

    stored.interaction.selected_session_oid = Some(session_oid);
    stored.interaction.selected_protected_session_id = protected_session_id;
    stored.interaction.selected_user_oid = Some(user_oid.to_string());
    stored.interaction.selection_source = Some(source);

    let now = Utc::now();
    let stored_data = to_value(stored).map_err(query_error(
        "client_authorization.update_authorization_request_selection",
    ))?;
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
        .exec(db)
        .await
        .map_err(query_error(
            "client_authorization.update_authorization_request_selection",
        ))?;

    Ok(result.rows_affected == 1)
}

#[tracing::instrument(skip_all, name = "db.query", fields(db.system = "postgresql", db.operation = "mark_authorization_request_completed"))]
pub(super) async fn mark_authorization_request_completed(
    db: &DatabaseConnection,
    oid: Uuid,
    completed_at: DateTime<Utc>,
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
        .exec(db)
        .await
        .map_err(query_error(
            "client_authorization.mark_authorization_request_completed",
        ))?;

    Ok(result.rows_affected == 1)
}

#[cfg(test)]
mod tests {
    use identity_domain::client_authorization::SelectionSource;

    #[test]
    fn reauthentication_cannot_be_replaced_by_another_selection_flow() {
        assert!(
            !SelectionSource::AccountPicker.can_replace(Some(SelectionSource::Reauthentication))
        );
        assert!(!SelectionSource::FreshLogin.can_replace(Some(SelectionSource::Reauthentication)));
        assert!(
            SelectionSource::Reauthentication.can_replace(Some(SelectionSource::Reauthentication))
        );
    }
}
