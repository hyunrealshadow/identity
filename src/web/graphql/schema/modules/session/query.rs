use crate::graphql::cursor::{ProtectedCursor, protect_many, unprotect};
use crate::graphql::schema::access::access;
use async_graphql::{
    Context, Object, Result,
    connection::{Connection, Edge},
};
use identity_application::error::codes::graphql;
use identity_domain::{auth::SessionOid, openid_connect::ApiScope, pagination::MAX_PAGE_SIZE};
use uuid::Uuid;

use super::{cursor::SessionCursor, types::SessionNode};
use crate::graphql::schema::{
    authorization::{ScopeGuard, UserPrincipalGuard, request_context},
    connection::validate_page_with_max,
    error::{app_error, internal_error},
};

#[derive(Default)]
pub(crate) struct SessionQuery;

#[Object]
impl SessionQuery {
    #[graphql(
        guard = "UserPrincipalGuard.and(ScopeGuard::new(ApiScope::SessionRead))",
        directive = access::apply(ScopeGuard::policy(ApiScope::SessionRead)),
        complexity = "crate::graphql::schema::connection::page_complexity(first, last, child_complexity)"
    )]
    async fn sessions(
        &self,
        ctx: &Context<'_>,
        after: Option<String>,
        before: Option<String>,
        #[graphql(validator(minimum = 1, maximum = 100))] first: Option<i32>,
        #[graphql(validator(minimum = 1, maximum = 100))] last: Option<i32>,
    ) -> Result<Connection<ProtectedCursor<SessionCursor>, SessionNode>> {
        let request = request_context(ctx)?;
        let current_session_oid = request.claims.session_oid;
        let user_oid = Uuid::from(request.user_oid()?);
        session_connection(
            ctx,
            user_oid,
            current_session_oid,
            after,
            before,
            first,
            last,
        )
        .await
    }
}

/// One page of `user_oid`'s active sessions, newest activity first.
/// `current_session_oid` marks the session behind the request, if any.
pub(crate) async fn session_connection(
    ctx: &Context<'_>,
    user_oid: Uuid,
    current_session_oid: Option<SessionOid>,
    after: Option<String>,
    before: Option<String>,
    first: Option<i32>,
    last: Option<i32>,
) -> Result<Connection<ProtectedCursor<SessionCursor>, SessionNode>> {
    let request = request_context(ctx)?;
    let max_page_size = ctx.data_opt::<usize>().copied().unwrap_or(MAX_PAGE_SIZE);
    let validated = validate_page_with_max(
        ctx,
        first,
        after.as_deref(),
        last,
        before.as_deref(),
        max_page_size,
    )?;

    let data_protector = request.state.services().data_protector().clone();
    let after = match validated.after {
        Some(token) => {
            let cursor = ProtectedCursor::<SessionCursor>::parse(token)
                .map_err(|_| app_error(ctx, graphql::error::InvalidCursor))?;
            Some(
                unprotect(data_protector.as_ref(), &cursor)
                    .await
                    .map_err(|_| app_error(ctx, graphql::error::InvalidCursor))?
                    .into_sort_key(),
            )
        }
        None => None,
    };
    let before = match validated.before {
        Some(token) => {
            let cursor = ProtectedCursor::<SessionCursor>::parse(token)
                .map_err(|_| app_error(ctx, graphql::error::InvalidCursor))?;
            Some(
                unprotect(data_protector.as_ref(), &cursor)
                    .await
                    .map_err(|_| app_error(ctx, graphql::error::InvalidCursor))?
                    .into_sort_key(),
            )
        }
        None => None,
    };

    let page = request
        .state
        .services()
        .session()
        .list_active_sessions_page(
            user_oid,
            after,
            before,
            validated.limit,
            validated.direction,
        )
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
    connection.edges.extend(
        page.items
            .into_iter()
            .zip(protected_cursors)
            .map(|(item, cursor)| {
                Edge::new(cursor, SessionNode::new(item.session, current_session_oid))
            }),
    );
    Ok(connection)
}
