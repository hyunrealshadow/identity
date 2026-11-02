use crate::graphql::schema::access::access;
use async_graphql::{
    Context, Object, Result,
    connection::{Connection, Edge, query},
};
use identity_application::error::{codes::graphql::GraphqlErrorCode, params::ErrorParams};
use identity_domain::{auth::repository::SessionPageDirection, openid_connect::ApiScope};
use identity_infrastructure::graphql::cursor::{ProtectedCursor, protect_many, unprotect};
use uuid::Uuid;

use super::{cursor::SessionCursor, types::SessionNode};
use crate::graphql::schema::{
    authorization::{ScopeGuard, UserPrincipalGuard, request_context},
    error::{coded_error, internal_error},
};

#[derive(Default)]
pub(crate) struct SessionQuery;

#[Object]
impl SessionQuery {
    #[graphql(guard = "UserPrincipalGuard.and(ScopeGuard::new(ApiScope::SessionRead))",
        directive = access::apply(ScopeGuard::policy(ApiScope::SessionRead)))]
    async fn sessions(
        &self,
        ctx: &Context<'_>,
        after: Option<String>,
        before: Option<String>,
        #[graphql(validator(minimum = 1))] first: Option<i32>,
        #[graphql(validator(minimum = 1))] last: Option<i32>,
    ) -> Result<Connection<ProtectedCursor<SessionCursor>, SessionNode>> {
        let request = request_context(ctx)?;
        let max_page_size = ctx.data_opt::<usize>().copied().unwrap_or(100);
        let requested = first.or(last).unwrap_or(20);
        if requested > 0 && requested as usize > max_page_size {
            let params = ErrorParams::new().insert("max", max_page_size.to_string());
            return Err(coded_error(ctx, GraphqlErrorCode::PageSizeInvalid, params));
        }
        if first.is_some() && last.is_some() {
            return Err(coded_error(
                ctx,
                GraphqlErrorCode::PageArgumentsConflict,
                ErrorParams::new(),
            ));
        }
        let state = request.state.clone();
        let current_session_oid = request.claims.session_oid;
        let user_oid = Uuid::from(request.user_oid()?);
        let data_protector = request.state.services().data_protector().clone();

        query(
            after,
            before,
            first,
            last,
            move |after: Option<ProtectedCursor<SessionCursor>>,
                  before: Option<ProtectedCursor<SessionCursor>>,
                  first,
                  last| async move {
                let requested = first.or(last).unwrap_or(20);
                let direction = if last.is_some() {
                    SessionPageDirection::Backward
                } else {
                    SessionPageDirection::Forward
                };
                let after = match after.as_ref() {
                    Some(cursor) => Some(
                        unprotect(data_protector.as_ref(), cursor)
                            .await
                            .map_err(|_| {
                                coded_error(
                                    ctx,
                                    GraphqlErrorCode::InvalidCursor,
                                    ErrorParams::new(),
                                )
                            })?
                            .into_sort_key(),
                    ),
                    None => None,
                };
                let before = match before.as_ref() {
                    Some(cursor) => Some(
                        unprotect(data_protector.as_ref(), cursor)
                            .await
                            .map_err(|_| {
                                coded_error(
                                    ctx,
                                    GraphqlErrorCode::InvalidCursor,
                                    ErrorParams::new(),
                                )
                            })?
                            .into_sort_key(),
                    ),
                    None => None,
                };
                let page = state
                    .services()
                    .session()
                    .list_active_sessions_page(user_oid, after, before, requested, direction)
                    .await
                    .map_err(|error| internal_error(ctx, error))?;
                let cursor_payloads = page
                    .items
                    .iter()
                    .map(|item| SessionCursor::new(item.sort_key.last_active_at, item.sort_key.id))
                    .collect::<Vec<_>>();
                let protected_cursors = protect_many(data_protector.as_ref(), &cursor_payloads)
                    .await
                    .map_err(|error| internal_error(ctx, error))?;
                let mut connection = Connection::new(page.has_previous_page, page.has_next_page);
                connection
                    .edges
                    .extend(
                        page.items
                            .into_iter()
                            .zip(protected_cursors)
                            .map(|(item, cursor)| {
                                Edge::new(
                                    cursor,
                                    SessionNode::new(item.session, current_session_oid),
                                )
                            }),
                    );
                Ok::<_, async_graphql::Error>(connection)
            },
        )
        .await
    }
}
