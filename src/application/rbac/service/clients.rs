use std::collections::BTreeMap;

use super::*;

use identity_domain::client::model::ClientOid;

use crate::rbac::client::{ClientScopeAssignment, ClientScopePage, ClientScopePageItem};

impl RbacManagementService {
    #[tracing::instrument(skip_all, name = "rbac.client_scope.count")]
    pub async fn count_client_scopes(&self, client_oid: ClientOid) -> Result<u64, AppError> {
        self.repository
            .count_client_scopes(client_oid)
            .await
            .map_err(map_repository_error)
    }

    #[tracing::instrument(skip_all, name = "rbac.client_scopes.list")]
    pub async fn list_client_scopes(
        &self,
        request: ClientScopePageRequest,
    ) -> Result<ClientScopePage, AppError> {
        let order = request.order;
        let fingerprint_input = (request.client_oid,);
        let prepared = prepare_page(
            self.data_protector.as_ref(),
            CURSOR_KIND_CLIENT_SCOPE,
            order.as_u8(),
            &fingerprint_input,
            PageArguments {
                first: request.first,
                after: request.after,
                last: request.last,
                before: request.before,
            },
        )
        .await?;
        let data = self
            .repository
            .list_client_scopes(ClientScopeQuery {
                client_oid: request.client_oid,
                order,
                direction: prepared.direction,
                after: prepared.after,
                before: prepared.before,
                limit: prepared.limit,
            })
            .await
            .map_err(map_repository_error)?;
        let mut items = Vec::with_capacity(data.items.len());
        for entry in data.items {
            let cursor = encode_cursor(
                self.data_protector.as_ref(),
                CURSOR_KIND_CLIENT_SCOPE,
                order.as_u8(),
                &prepared.filter_fingerprint,
                &entry.sort_key,
            )
            .await?;
            items.push(ClientScopePageItem {
                record: entry.record,
                client_granted: entry.client_granted,
                cursor,
            });
        }
        Ok(ClientScopePage {
            items,
            has_previous_page: data.has_previous_page,
            has_next_page: data.has_next_page,
        })
    }

    #[tracing::instrument(skip_all, name = "rbac.client_scopes.set")]
    pub async fn set_client_scopes(
        &self,
        authority: &RbacManagementAuthority,
        command: SetClientScopesCommand,
    ) -> Result<ClientScopeSetResult, AppError> {
        let result = async {
            let reason = validate_reason(&command.reason)?;
            validate_client_mutation_id(command.client_mutation_id.as_deref())?;

            if command.scopes.len() > MAX_SCOPE_ASSIGNMENTS {
                return Err(AppError::from_code(RbacErrorCode::InvalidCollectionSize)
                    .with_param("max", MAX_SCOPE_ASSIGNMENTS.to_string())
                    .with_field("scopes"));
            }
            let scopes = normalize_client_scope_assignments(command.scopes)?;
            let result = self
                .repository
                .set_client_scopes(SetClientScopesTransaction {
                    client_oid: command.client_oid,
                    scopes,
                    expected_version: command.expected_version,
                    reason,
                    authority: authority.clone(),
                })
                .await
                .map_err(|error| map_delegation_error(error, "scopes"))?;
            Ok(result)
        }
        .await;
        self.emit_result("rbac.client_scopes.set", &result, "client_oid");
        result
    }
}

/// Collapse exact duplicates; the same scope with conflicting grant flags is
/// ambiguous and rejected rather than silently resolved.
fn normalize_client_scope_assignments(
    scopes: Vec<ClientScopeAssignment>,
) -> Result<Vec<ClientScopeAssignment>, AppError> {
    let mut unique = BTreeMap::new();
    for assignment in scopes {
        match unique.insert(assignment.scope_oid, assignment.client_granted) {
            Some(previous) if previous != assignment.client_granted => {
                return Err(AppError::from_code(RbacErrorCode::ValidationFailed)
                    .with_param("field", "scopes")
                    .with_field("scopes"));
            }
            _ => {}
        }
    }
    Ok(unique
        .into_iter()
        .map(|(scope_oid, client_granted)| ClientScopeAssignment {
            scope_oid,
            client_granted,
        })
        .collect())
}

#[cfg(test)]
mod tests {
    use uuid::Uuid;

    use super::normalize_client_scope_assignments;
    use crate::{
        error::code::AppErrorCode,
        error::codes::rbac::RbacErrorCode,
        rbac::{ScopeOid, client::ClientScopeAssignment},
    };

    fn assignment(scope_oid: ScopeOid, client_granted: bool) -> ClientScopeAssignment {
        ClientScopeAssignment {
            scope_oid,
            client_granted,
        }
    }

    #[test]
    fn duplicate_assignments_collapse_but_conflicting_grants_are_rejected() {
        let scope = ScopeOid(Uuid::new_v4());
        assert_eq!(
            normalize_client_scope_assignments(vec![
                assignment(scope, true),
                assignment(scope, true)
            ])
            .unwrap(),
            vec![assignment(scope, true)]
        );
        let error = normalize_client_scope_assignments(vec![
            assignment(scope, true),
            assignment(scope, false),
        ])
        .unwrap_err();
        assert_eq!(error.code(), RbacErrorCode::ValidationFailed.code());
    }
}
