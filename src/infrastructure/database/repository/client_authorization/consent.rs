use super::{
    mapping::parse_stored_authorization_request, request_interaction::selection_update_condition,
};
use super::{query_error, query_failed};
use crate::database::entity::{
    client, client::Entity as ClientEntity, client_authorization,
    client_authorization::Entity as ClientAuthorizationEntity, resource, scope,
    scope::Entity as ScopeEntity, user, user::Entity as UserEntity, user_client_consent,
    user_client_consent::Entity as UserClientConsentEntity,
};
use chrono::{DateTime, Utc};
use identity_domain::{
    client::model::ClientOid,
    client_authorization::{
        ClientAuthorizationRepositoryError, ClientAuthorizationType, ConsentState,
    },
    openid_connect::{API_RESOURCE, ScopeSet},
};
use sea_orm::{
    ColumnTrait, Condition, DatabaseConnection, DbErr, EntityTrait, QueryFilter, QuerySelect,
    QueryTrait, Set, TransactionTrait,
    sea_query::{OnConflict, SimpleExpr},
};
use serde_json::to_value;
use uuid::Uuid;

fn scope_ids_cover(mut granted: Vec<i64>, mut requested: Vec<i64>) -> bool {
    granted.sort_unstable();
    granted.dedup();
    requested.sort_unstable();
    requested.dedup();

    requested
        .iter()
        .all(|scope_id| granted.binary_search(scope_id).is_ok())
}

/// Match protocol scopes and only the requested API resource ownership.
fn scope_ownership(resources: &[String]) -> Condition {
    let targets = if resources.is_empty() {
        vec![API_RESOURCE.to_owned()]
    } else {
        resources.to_vec()
    };
    Condition::any()
        .add(scope::Column::ResourceId.is_null())
        .add(
            scope::Column::ResourceId.in_subquery(
                resource::Entity::find()
                    .select_only()
                    .column(resource::Column::Oid)
                    .filter(resource::Column::Uri.is_in(targets))
                    .filter(resource::Column::Enabled.eq(true))
                    .into_query(),
            ),
        )
}

#[tracing::instrument(skip_all, name = "db.query", fields(db.system = "postgresql", db.operation = "record_authorization_request_consent"))]
pub(super) async fn record_authorization_request_consent(
    db: &DatabaseConnection,
    oid: Uuid,
    consent_state: ConsentState,
    decided_at: DateTime<Utc>,
) -> Result<bool, ClientAuthorizationRepositoryError> {
    let Some(model) = ClientAuthorizationEntity::find()
        .filter(client_authorization::Column::Oid.eq(oid))
        .one(db)
        .await
        .map_err(query_error(
            "client_authorization.record_authorization_request_consent",
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
    if stored.interaction.consent_state != ConsentState::Pending {
        return Ok(false);
    }

    let grant = if consent_state == ConsentState::Approved {
        let user_oid = stored
            .interaction
            .selected_user_oid
            .as_deref()
            .ok_or_else(|| {
                query_failed(
                    "client_authorization.record_authorization_request_consent",
                    DbErr::Type("approved consent has no selected user".into()),
                )
            })?
            .parse::<Uuid>()
            .map_err(query_error(
                "client_authorization.record_authorization_request_consent",
            ))?;
        let scope = ScopeSet::parse(&stored.request.scope).map_err(query_error(
            "client_authorization.record_authorization_request_consent",
        ))?;
        Some((user_oid, scope, stored.request.resources.clone()))
    } else {
        None
    };

    stored.interaction.consent_state = consent_state;
    stored.interaction.consent_decided_at = Some(decided_at.to_rfc3339());

    let now = Utc::now();
    let stored_data = to_value(stored).map_err(query_error(
        "client_authorization.record_authorization_request_consent",
    ))?;
    let transaction = db.begin().await.map_err(query_error(
        "client_authorization.record_authorization_request_consent",
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
        .exec(&transaction)
        .await
        .map_err(query_error(
            "client_authorization.record_authorization_request_consent",
        ))?;

    if result.rows_affected != 1 {
        return Ok(false);
    }

    if let Some((user_oid, requested_scope, resources)) = grant {
        let user_id = UserEntity::find()
            .select_only()
            .column(user::Column::Id)
            .filter(user::Column::Oid.eq(user_oid))
            .into_tuple::<i64>()
            .one(&transaction)
            .await
            .map_err(query_error(
                "client_authorization.record_authorization_request_consent",
            ))?
            .ok_or_else(|| {
                query_failed(
                    "client_authorization.record_authorization_request_consent",
                    DbErr::RecordNotFound(format!("user {user_oid} not found")),
                )
            })?;
        let requested_scope_names = requested_scope.names();
        let mut scope_ids = ScopeEntity::find()
            .select_only()
            .column(scope::Column::Id)
            .filter(scope::Column::Code.is_in(requested_scope_names.iter().copied()))
            .filter(scope::Column::Enabled.eq(true))
            .filter(scope_ownership(&resources))
            .into_tuple::<i64>()
            .all(&transaction)
            .await
            .map_err(query_error(
                "client_authorization.record_authorization_request_consent",
            ))?;
        scope_ids.sort_unstable();
        scope_ids.dedup();
        if scope_ids.len() != requested_scope_names.len() {
            return Err(query_failed(
                "client_authorization.record_authorization_request_consent",
                DbErr::RecordNotFound("one or more consent scopes were not found".to_owned()),
            ));
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
            .map_err(query_error(
                "client_authorization.record_authorization_request_consent",
            ))?;
    }

    crate::database::audit::record(
        &transaction,
        if consent_state == ConsentState::Approved {
            "authorization.consent_approved"
        } else {
            "authorization.consent_denied"
        },
        "client_authorization",
        oid,
    )
    .await
    .map_err(query_error(
        "client_authorization.record_authorization_request_consent",
    ))?;
    transaction.commit().await.map_err(query_error(
        "client_authorization.record_authorization_request_consent",
    ))?;
    Ok(true)
}

#[tracing::instrument(skip_all, name = "db.query", fields(db.system = "postgresql", db.operation = "has_user_consent"))]
pub(super) async fn has_user_consent(
    db: &DatabaseConnection,
    user_oid: Uuid,
    client_oid: ClientOid,
    requested_scope: &ScopeSet,
    resources: &[String],
) -> Result<bool, ClientAuthorizationRepositoryError> {
    let Some(user) = UserEntity::find()
        .filter(user::Column::Oid.eq(user_oid))
        .one(db)
        .await
        .map_err(query_error("client_authorization.has_user_consent"))?
    else {
        return Ok(false);
    };
    let Some(client) = ClientEntity::find()
        .filter(client::Column::Oid.eq(client_oid))
        .one(db)
        .await
        .map_err(query_error("client_authorization.has_user_consent"))?
    else {
        return Ok(false);
    };
    let requested_scope_names = requested_scope.names();
    let mut requested_scope_ids = ScopeEntity::find()
        .select_only()
        .column(scope::Column::Id)
        .filter(scope::Column::Code.is_in(requested_scope_names.iter().copied()))
        .filter(scope::Column::Enabled.eq(true))
        .filter(scope_ownership(resources))
        .into_tuple::<i64>()
        .all(db)
        .await
        .map_err(query_error("client_authorization.has_user_consent"))?;
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
        .all(db)
        .await
        .map_err(query_error("client_authorization.has_user_consent"))?;
    Ok(scope_ids_cover(granted_scope_ids, requested_scope_ids))
}

#[tracing::instrument(skip_all, name = "db.query", fields(db.system = "postgresql", db.operation = "user_consented_scope_names"))]
pub(super) async fn user_consented_scope_names(
    db: &DatabaseConnection,
    user_oid: Uuid,
    client_oid: ClientOid,
    resources: &[String],
) -> Result<Vec<String>, ClientAuthorizationRepositoryError> {
    UserClientConsentEntity::find()
        .select_only()
        .column(scope::Column::Code)
        .inner_join(UserEntity)
        .inner_join(ClientEntity)
        .inner_join(ScopeEntity)
        .filter(user::Column::Oid.eq(user_oid))
        .filter(client::Column::Oid.eq(client_oid))
        .filter(scope::Column::Enabled.eq(true))
        .filter(scope_ownership(resources))
        .into_tuple::<String>()
        .all(db)
        .await
        .map_err(query_error(
            "client_authorization.user_consented_scope_names",
        ))
}

#[cfg(test)]
mod tests {
    use super::scope_ids_cover;
    #[test]
    fn consent_scope_comparison_sorts_deduplicates_and_accepts_subsets() {
        assert!(scope_ids_cover(vec![3, 1, 2, 2], vec![2, 1, 1]));
        assert!(!scope_ids_cover(vec![3, 1, 1], vec![1, 2]));
    }
}
