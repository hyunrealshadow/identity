use std::error::Error as _;

use async_graphql::{
    Context, EmptySubscription, Error, ErrorExtensions, ID, InputObject, Interface, MaybeUndefined,
    Object, Result, Schema,
    connection::{Connection, Edge, query},
};
use identity_application::error::{AppError, kind::ErrorKind};
use identity_application::openid_connect::user_info::TokenClaims;
use identity_domain::{
    auth::{SessionOid, model::Session},
    openid_connect::ApiScope,
    user::{User, repository::UserRepository},
};
use identity_infrastructure::{
    AppState,
    database::repository::{
        session::SessionRepositoryImpl,
        user::{UserProfilePatch, UserRepositoryImpl},
    },
};
use uuid::Uuid;

use super::{cursor::SessionCursor, id::NodeId};

pub type ApiSchema = Schema<QueryRoot, MutationRoot, EmptySubscription>;

pub const RESOURCE_AUDIENCE: &str = "urn:identity:graphql";

pub struct RequestContext {
    pub state: AppState,
    pub claims: TokenClaims,
    pub user: User,
    pub locale: unic_langid::LanguageIdentifier,
    pub request_id: String,
}

pub fn build_schema(max_depth: usize, max_complexity: usize) -> ApiSchema {
    Schema::build(QueryRoot, MutationRoot, EmptySubscription)
        .limit_depth(max_depth)
        .limit_complexity(max_complexity)
        .finish()
}

pub struct QueryRoot;

#[Object]
impl QueryRoot {
    async fn viewer(&self) -> Viewer {
        Viewer
    }

    async fn node(&self, ctx: &Context<'_>, id: ID) -> Result<Option<Node>> {
        load_node(ctx, &id).await
    }

    async fn nodes(&self, ctx: &Context<'_>, ids: Vec<ID>) -> Vec<Result<Option<Node>>> {
        let mut nodes = Vec::with_capacity(ids.len());
        for id in ids {
            nodes.push(load_node(ctx, &id).await);
        }
        nodes
    }
}

pub struct Viewer;

#[Object]
impl Viewer {
    async fn account(&self, ctx: &Context<'_>) -> Result<Option<UserNode>> {
        require_scope(ctx, ApiScope::AccountRead)?;
        Ok(Some(UserNode::from(request_context(ctx)?.user.clone())))
    }

    async fn sessions(
        &self,
        ctx: &Context<'_>,
        after: Option<String>,
        before: Option<String>,
        first: Option<i32>,
        last: Option<i32>,
    ) -> Result<Connection<SessionCursor, SessionNode>> {
        require_scope(ctx, ApiScope::SessionRead)?;
        let request = request_context(ctx)?;
        let max_page_size = ctx.data_opt::<usize>().copied().unwrap_or(100);
        let repo = SessionRepositoryImpl::new(request.state.resources().db().clone());
        let sessions = repo
            .list_by_user_oid(Uuid::from(request.claims.user_oid))
            .await
            .map_err(internal_error)?;

        query(
            after,
            before,
            first,
            last,
            move |after, before, first, last| async move {
                let requested = first.or(last).unwrap_or(20);
                if requested > max_page_size {
                    return Err(Error::new(format!(
                        "page size cannot exceed {max_page_size}"
                    )));
                }

                let mut start = 0usize;
                let mut end = sessions.len();
                if let Some(after) = after
                    && let Some(position) = sessions
                        .iter()
                        .position(|session| session_cursor(session) == after)
                {
                    start = position + 1;
                }
                if let Some(before) = before
                    && let Some(position) = sessions
                        .iter()
                        .position(|session| session_cursor(session) == before)
                {
                    end = position;
                }
                start = start.min(end);
                let available = &sessions[start..end];
                let (slice_start, slice_end) = if let Some(last) = last {
                    (available.len().saturating_sub(last), available.len())
                } else {
                    (0, first.unwrap_or(20).min(available.len()))
                };
                let mut connection =
                    Connection::new(start + slice_start > 0, start + slice_end < sessions.len());
                connection
                    .edges
                    .extend(
                        available[slice_start..slice_end]
                            .iter()
                            .cloned()
                            .map(|session| {
                                Edge::new(
                                    session_cursor(&session),
                                    SessionNode::new(session, request.claims.session_oid),
                                )
                            }),
                    );
                Ok::<_, Error>(connection)
            },
        )
        .await
    }
}

#[derive(Interface)]
#[graphql(field(name = "id", ty = "&ID"))]
pub enum Node {
    User(Box<UserNode>),
    Session(Box<SessionNode>),
}

pub struct UserNode {
    id: ID,
    user: User,
}

impl From<User> for UserNode {
    fn from(user: User) -> Self {
        Self {
            id: ID(NodeId::User(Uuid::from(user.oid)).encode()),
            user,
        }
    }
}

#[Object(name = "User")]
impl UserNode {
    async fn id(&self) -> &ID {
        &self.id
    }

    async fn username(&self) -> &str {
        &self.user.name
    }

    async fn email(&self) -> &str {
        &self.user.email
    }

    async fn email_verified(&self) -> bool {
        self.user.email_verified
    }

    async fn given_name(&self) -> Option<&str> {
        self.user.given_name.as_deref()
    }

    async fn family_name(&self) -> Option<&str> {
        self.user.family_name.as_deref()
    }

    async fn middle_name(&self) -> Option<&str> {
        self.user.middle_name.as_deref()
    }

    async fn nickname(&self) -> Option<&str> {
        self.user.nickname.as_deref()
    }

    async fn profile(&self) -> Option<&str> {
        self.user.profile.as_deref()
    }

    async fn picture(&self) -> Option<&str> {
        self.user.picture.as_deref()
    }

    async fn website(&self) -> Option<&str> {
        self.user.website.as_deref()
    }

    async fn locale(&self) -> Option<&str> {
        self.user.locale.as_deref()
    }

    async fn phone_number(&self) -> Option<&str> {
        self.user.phone_number.as_deref()
    }

    async fn phone_number_verified(&self) -> Option<bool> {
        self.user.phone_number_verified
    }

    async fn created_at(&self) -> chrono::DateTime<chrono::Utc> {
        self.user.created_at
    }

    async fn updated_at(&self) -> Option<chrono::DateTime<chrono::Utc>> {
        self.user.updated_at
    }
}

pub struct SessionNode {
    id: ID,
    session: Session,
    current: bool,
}

impl SessionNode {
    fn new(session: Session, current_session_oid: SessionOid) -> Self {
        Self {
            id: ID(NodeId::Session(Uuid::from(session.oid)).encode()),
            current: session.oid == current_session_oid,
            session,
        }
    }
}

#[Object(name = "Session")]
impl SessionNode {
    async fn id(&self) -> &ID {
        &self.id
    }

    async fn status(&self) -> &str {
        &self.session.status
    }

    async fn current(&self) -> bool {
        self.current
    }

    async fn device_name(&self) -> Option<&str> {
        self.session.device_name.as_deref()
    }

    async fn device_type(&self) -> Option<&str> {
        self.session.device_type.as_deref()
    }

    async fn os_name(&self) -> Option<&str> {
        self.session.os_name.as_deref()
    }

    async fn os_version(&self) -> Option<&str> {
        self.session.os_version.as_deref()
    }

    async fn browser_name(&self) -> Option<&str> {
        self.session.browser_name.as_deref()
    }

    async fn browser_version(&self) -> Option<&str> {
        self.session.browser_version.as_deref()
    }

    async fn ip_address(&self) -> Option<&str> {
        self.session.ip_address.as_deref()
    }

    async fn last_active_at(&self) -> Option<chrono::DateTime<chrono::Utc>> {
        self.session.last_active_at
    }

    async fn expires_at(&self) -> Option<chrono::DateTime<chrono::Utc>> {
        self.session.expires_at
    }

    async fn created_at(&self) -> chrono::DateTime<chrono::Utc> {
        self.session.created_at
    }
}

pub struct MutationRoot;

#[Object]
impl MutationRoot {
    async fn update_profile(
        &self,
        ctx: &Context<'_>,
        input: UpdateProfileInput,
    ) -> Result<UpdateProfilePayload> {
        require_scope(ctx, ApiScope::AccountUpdate)?;
        let request = request_context(ctx)?;
        let repo = UserRepositoryImpl::new(request.state.resources().db().clone());
        let user = repo
            .update_profile(request.claims.user_oid, input.clone().into_patch())
            .await
            .map_err(internal_error)?
            .ok_or_else(|| Error::new("account not found"))?;
        Ok(UpdateProfilePayload {
            user: UserNode::from(user),
            client_mutation_id: input.client_mutation_id,
        })
    }

    async fn change_password(
        &self,
        ctx: &Context<'_>,
        input: ChangePasswordInput,
    ) -> Result<ChangePasswordPayload> {
        require_scope(ctx, ApiScope::PasswordChange)?;
        let request = request_context(ctx)?;
        let now = chrono::Utc::now().timestamp();
        if request
            .claims
            .auth_time
            .is_none_or(|auth_time| now.saturating_sub(auth_time) > 300)
            || request.claims.acr.is_none()
        {
            return Err(Error::new("recent authentication is required").extend_with(
                |_, extensions| {
                    extensions.set("kind", "authorization_error");
                    extensions.set("code", "FRESH_AUTHENTICATION_REQUIRED");
                },
            ));
        }
        request
            .state
            .services()
            .login()
            .change_password(
                request.claims.user_oid,
                &input.current_password,
                &input.new_password,
            )
            .await
            .map_err(|error| app_error(ctx, error))?;

        let repo = SessionRepositoryImpl::new(request.state.resources().db().clone());
        let sessions = repo
            .list_by_user_oid(Uuid::from(request.claims.user_oid))
            .await
            .map_err(internal_error)?;
        for session in sessions
            .into_iter()
            .filter(|session| session.oid != request.claims.session_oid)
            .filter(|session| session.revoked_at.is_none())
        {
            request
                .state
                .services()
                .session()
                .revoke(session.oid)
                .await
                .map_err(internal_error)?;
        }
        Ok(ChangePasswordPayload {
            changed: true,
            client_mutation_id: input.client_mutation_id,
        })
    }

    async fn revoke_session(
        &self,
        ctx: &Context<'_>,
        id: ID,
        client_mutation_id: Option<String>,
    ) -> Result<RevokeSessionPayload> {
        require_scope(ctx, ApiScope::SessionRevoke)?;
        let request = request_context(ctx)?;
        let NodeId::Session(oid) =
            NodeId::decode(id.as_str()).map_err(|_| Error::new("invalid session id"))?
        else {
            return Err(Error::new("invalid session id"));
        };
        let session = request
            .state
            .services()
            .session()
            .session_repo
            .find_by_oid(SessionOid(oid))
            .await
            .map_err(internal_error)?
            .ok_or_else(|| Error::new("session not found"))?;
        if session.user_oid != Uuid::from(request.claims.user_oid) {
            return Err(Error::new("session not found"));
        }
        let session = request
            .state
            .services()
            .session()
            .revoke(session.oid)
            .await
            .map_err(internal_error)?;
        Ok(RevokeSessionPayload {
            session: SessionNode::new(session, request.claims.session_oid),
            client_mutation_id,
        })
    }

    async fn revoke_other_sessions(
        &self,
        ctx: &Context<'_>,
        client_mutation_id: Option<String>,
    ) -> Result<RevokeOtherSessionsPayload> {
        require_scope(ctx, ApiScope::SessionRevoke)?;
        let request = request_context(ctx)?;
        let repo = SessionRepositoryImpl::new(request.state.resources().db().clone());
        let sessions = repo
            .list_by_user_oid(Uuid::from(request.claims.user_oid))
            .await
            .map_err(internal_error)?;
        let mut revoked_count = 0;
        for session in sessions
            .into_iter()
            .filter(|session| session.oid != request.claims.session_oid)
            .filter(|session| session.status == identity_domain::auth::SessionStatus::ACTIVE)
            .filter(|session| session.revoked_at.is_none())
        {
            request
                .state
                .services()
                .session()
                .revoke(session.oid)
                .await
                .map_err(internal_error)?;
            revoked_count += 1;
        }
        Ok(RevokeOtherSessionsPayload {
            revoked_count,
            client_mutation_id,
        })
    }
}

#[derive(InputObject)]
pub struct ChangePasswordInput {
    pub current_password: String,
    pub new_password: String,
    pub client_mutation_id: Option<String>,
}

pub struct ChangePasswordPayload {
    changed: bool,
    client_mutation_id: Option<String>,
}

#[Object]
impl ChangePasswordPayload {
    async fn changed(&self) -> bool {
        self.changed
    }

    async fn client_mutation_id(&self) -> Option<&str> {
        self.client_mutation_id.as_deref()
    }
}

#[derive(Clone, InputObject)]
pub struct UpdateProfileInput {
    pub given_name: MaybeUndefined<String>,
    pub family_name: MaybeUndefined<String>,
    pub middle_name: MaybeUndefined<String>,
    pub nickname: MaybeUndefined<String>,
    pub profile: MaybeUndefined<String>,
    pub picture: MaybeUndefined<String>,
    pub website: MaybeUndefined<String>,
    pub gender: MaybeUndefined<String>,
    pub birthdate: MaybeUndefined<String>,
    pub zone_info: MaybeUndefined<String>,
    pub locale: MaybeUndefined<String>,
    pub phone_number: MaybeUndefined<String>,
    pub address_formatted: MaybeUndefined<String>,
    pub address_street_address: MaybeUndefined<String>,
    pub address_locality: MaybeUndefined<String>,
    pub address_region: MaybeUndefined<String>,
    pub address_postal_code: MaybeUndefined<String>,
    pub address_country: MaybeUndefined<String>,
    pub client_mutation_id: Option<String>,
}

impl UpdateProfileInput {
    fn into_patch(self) -> UserProfilePatch {
        UserProfilePatch {
            given_name: patch_value(self.given_name),
            family_name: patch_value(self.family_name),
            middle_name: patch_value(self.middle_name),
            nickname: patch_value(self.nickname),
            profile: patch_value(self.profile),
            picture: patch_value(self.picture),
            website: patch_value(self.website),
            gender: patch_value(self.gender),
            birthdate: patch_value(self.birthdate),
            zone_info: patch_value(self.zone_info),
            locale: patch_value(self.locale),
            phone_number: patch_value(self.phone_number),
            address_formatted: patch_value(self.address_formatted),
            address_street_address: patch_value(self.address_street_address),
            address_locality: patch_value(self.address_locality),
            address_region: patch_value(self.address_region),
            address_postal_code: patch_value(self.address_postal_code),
            address_country: patch_value(self.address_country),
        }
    }
}

fn patch_value(value: MaybeUndefined<String>) -> Option<Option<String>> {
    match value {
        MaybeUndefined::Undefined => None,
        MaybeUndefined::Null => Some(None),
        MaybeUndefined::Value(value) => Some(Some(value.trim().to_string())),
    }
}

pub struct UpdateProfilePayload {
    user: UserNode,
    client_mutation_id: Option<String>,
}

#[Object]
impl UpdateProfilePayload {
    async fn user(&self) -> &UserNode {
        &self.user
    }

    async fn client_mutation_id(&self) -> Option<&str> {
        self.client_mutation_id.as_deref()
    }
}

pub struct RevokeSessionPayload {
    session: SessionNode,
    client_mutation_id: Option<String>,
}

#[Object]
impl RevokeSessionPayload {
    async fn session(&self) -> &SessionNode {
        &self.session
    }

    async fn client_mutation_id(&self) -> Option<&str> {
        self.client_mutation_id.as_deref()
    }
}

pub struct RevokeOtherSessionsPayload {
    revoked_count: i32,
    client_mutation_id: Option<String>,
}

#[Object]
impl RevokeOtherSessionsPayload {
    async fn revoked_count(&self) -> i32 {
        self.revoked_count
    }

    async fn client_mutation_id(&self) -> Option<&str> {
        self.client_mutation_id.as_deref()
    }
}

async fn load_node(ctx: &Context<'_>, id: &ID) -> Result<Option<Node>> {
    let request = request_context(ctx)?;
    match NodeId::decode(id.as_str()).map_err(|_| Error::new("invalid node id"))? {
        NodeId::User(oid) => {
            require_scope(ctx, ApiScope::AccountRead)?;
            if oid != Uuid::from(request.claims.user_oid) {
                return Ok(None);
            }
            let repo = UserRepositoryImpl::new(request.state.resources().db().clone());
            Ok(repo
                .find_by_oid(request.claims.user_oid)
                .await
                .map_err(internal_error)?
                .map(UserNode::from)
                .map(Box::new)
                .map(Node::from))
        }
        NodeId::Session(oid) => {
            require_scope(ctx, ApiScope::SessionRead)?;
            let session = request
                .state
                .services()
                .session()
                .session_repo
                .find_by_oid(SessionOid(oid))
                .await
                .map_err(internal_error)?;
            Ok(session
                .filter(|session| session.user_oid == Uuid::from(request.claims.user_oid))
                .map(|session| SessionNode::new(session, request.claims.session_oid))
                .map(Box::new)
                .map(Node::from))
        }
    }
}

fn request_context<'a>(ctx: &'a Context<'_>) -> Result<&'a RequestContext> {
    ctx.data::<RequestContext>()
        .map_err(|_| Error::new("authentication context is unavailable"))
}

fn require_scope(ctx: &Context<'_>, scope: ApiScope) -> Result<()> {
    if request_context(ctx)?.claims.scope.allows(scope) {
        Ok(())
    } else {
        Err(
            Error::new("insufficient scope").extend_with(|_, extensions| {
                extensions.set("kind", "authorization_error");
                extensions.set("requiredScope", scope.name());
            }),
        )
    }
}

fn internal_error(error: impl std::fmt::Display) -> Error {
    tracing::error!(error = %error, "graphql resolver failed");
    Error::new("internal server error")
}

fn app_error(ctx: &Context<'_>, error: AppError) -> Error {
    let request = match request_context(ctx) {
        Ok(request) => request,
        Err(error) => return error,
    };
    if error.kind() == ErrorKind::Internal {
        tracing::error!(
            error = %error,
            source = ?error.source(),
            code = error.code(),
            request_id = request.request_id,
            "graphql application error"
        );
    }
    let i18n = request.state.resources().i18n();
    let message = crate::controllers::response::error_message(i18n, &request.locale, &error);
    let kind = match error.kind() {
        ErrorKind::NotFound => "not_found",
        ErrorKind::Unauthorized => "unauthorized",
        ErrorKind::Forbidden => "forbidden",
        ErrorKind::Conflict => "conflict",
        ErrorKind::Validation => "validation",
        ErrorKind::RateLimit => "rate_limit",
        ErrorKind::Gone => "gone",
        ErrorKind::Internal => "internal",
    };
    let fields = error
        .validation()
        .map(|validation| {
            validation
                .fields()
                .iter()
                .map(|field| {
                    let field_message = field
                        .params()
                        .get("message")
                        .filter(|message| !message.is_empty())
                        .map(str::to_owned)
                        .unwrap_or_else(|| {
                            i18n.t_code_with_params(&request.locale, field.code(), field.params())
                        });
                    serde_json::json!({
                        "field": field.field(),
                        "code": field.code(),
                        "message": field_message,
                    })
                })
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    Error::new(message).extend_with(|_, extensions| {
        extensions.set("kind", kind);
        extensions.set("code", error.code());
        extensions.set("requestId", request.request_id.as_str());
        extensions.set(
            "fields",
            async_graphql::Value::from_json(serde_json::Value::Array(fields))
                .unwrap_or(async_graphql::Value::Null),
        );
    })
}

fn session_cursor(session: &Session) -> SessionCursor {
    SessionCursor::new(
        session.last_active_at.unwrap_or(session.created_at),
        session.created_at,
        Uuid::from(session.oid),
    )
}
