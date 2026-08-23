pub(super) mod account;
mod node;
mod security;
mod session;

use async_graphql::{MergedObject, Object};

use self::{
    account::{AccountMutation, AccountViewer},
    node::NodeQuery,
    security::{SecurityMutation, SecurityViewer},
    session::{SessionMutation, SessionViewer},
};

#[derive(MergedObject, Default)]
pub(crate) struct QueryRoot(ViewerQuery, NodeQuery);

#[derive(Default)]
struct ViewerQuery;

#[Object]
impl ViewerQuery {
    async fn viewer(&self) -> Viewer {
        Viewer::default()
    }
}

#[derive(MergedObject, Default)]
struct Viewer(AccountViewer, SecurityViewer, SessionViewer);

#[derive(MergedObject, Default)]
pub(crate) struct MutationRoot(AccountMutation, SecurityMutation, SessionMutation);
