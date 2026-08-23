use async_graphql::{
    Context, Error, Object, Result,
    connection::{Connection, Edge, query},
};
use identity_domain::openid_connect::ApiScope;
use identity_infrastructure::{
    database::repository::session::{SessionPageDirection, SessionRepositoryImpl},
    graphql::cursor::{ProtectedCursor, protect_many, unprotect},
};
use uuid::Uuid;

use super::{cursor::SessionCursor, types::SessionNode};
use crate::graphql::schema::{
    authorization::{request_context, require_scope},
    error::internal_error,
};

#[derive(Default)]
pub(crate) struct SessionViewer;

#[Object]
impl SessionViewer {
    async fn sessions(
        &self,
        ctx: &Context<'_>,
        after: Option<String>,
        before: Option<String>,
        first: Option<i32>,
        last: Option<i32>,
    ) -> Result<Connection<ProtectedCursor<SessionCursor>, SessionNode>> {
        require_scope(ctx, ApiScope::SessionRead)?;
        let request = request_context(ctx)?;
        let max_page_size = ctx.data_opt::<usize>().copied().unwrap_or(100);
        let repo = SessionRepositoryImpl::new(request.state.resources().db().clone());
        let current_session_oid = request.claims.session_oid;
        let user_oid = Uuid::from(request.claims.user_oid);
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
                if requested > max_page_size {
                    return Err(Error::new(format!(
                        "page size cannot exceed {max_page_size}"
                    )));
                }
                let direction = if last.is_some() {
                    SessionPageDirection::Backward
                } else {
                    SessionPageDirection::Forward
                };
                let after = match after.as_ref() {
                    Some(cursor) => Some(
                        unprotect(data_protector.as_ref(), cursor)
                            .await
                            .map_err(|_| Error::new("invalid session cursor"))?
                            .into_sort_key(),
                    ),
                    None => None,
                };
                let before = match before.as_ref() {
                    Some(cursor) => Some(
                        unprotect(data_protector.as_ref(), cursor)
                            .await
                            .map_err(|_| Error::new("invalid session cursor"))?
                            .into_sort_key(),
                    ),
                    None => None,
                };
                let page = repo
                    .list_active_page_by_user_oid(user_oid, after, before, requested, direction)
                    .await
                    .map_err(internal_error)?;
                let cursor_payloads = page
                    .items
                    .iter()
                    .map(|item| SessionCursor::new(item.sort_key.last_active_at, item.sort_key.id))
                    .collect::<Vec<_>>();
                let protected_cursors = protect_many(data_protector.as_ref(), &cursor_payloads)
                    .await
                    .map_err(internal_error)?;
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
                Ok::<_, Error>(connection)
            },
        )
        .await
    }
}
