use std::error::Error as _;

use async_graphql::{
    Context, EmptySubscription, Error, ErrorExtensions, ID, InputObject, Interface, MaybeUndefined,
    Object, Result, Schema,
    connection::{Connection, Edge, query},
};
use identity_application::openid_connect::user_info::TokenClaims;
use identity_application::{
    data_protection::DataProtector,
    error::{AppError, codes::account::AccountErrorCode, kind::ErrorKind},
};
use identity_domain::{
    auth::{SessionOid, model::Session},
    openid_connect::ApiScope,
    user::{
        User,
        normalization::{EmailNormalizationError, UsernameValidationError},
        repository::{UserRepository, UserRepositoryError},
    },
};
use identity_infrastructure::{
    AppState,
    database::repository::{
        session::SessionRepositoryImpl,
        session::{SessionPageDirection, SessionSortKey},
        user::{UserIdentifierPatch, UserProfilePatch, UserRepositoryImpl},
    },
};
use uuid::Uuid;

use super::{
    cursor::{ProtectedSessionCursor, SessionCursor},
    id::NodeId,
};

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

    async fn security(&self, ctx: &Context<'_>) -> Result<AccountSecurity> {
        require_scope(ctx, ApiScope::AccountRead)?;
        let request = request_context(ctx)?;
        let status = request
            .state
            .services()
            .mfa()
            .status(request.claims.user_oid)
            .await
            .map_err(|error| app_error(ctx, error))?;
        Ok(AccountSecurity {
            totp_enabled: status.totp_enabled,
            recovery_codes_remaining: status.recovery_codes_remaining as i32,
        })
    }

    async fn sessions(
        &self,
        ctx: &Context<'_>,
        after: Option<String>,
        before: Option<String>,
        first: Option<i32>,
        last: Option<i32>,
    ) -> Result<Connection<ProtectedSessionCursor, SessionNode>> {
        require_scope(ctx, ApiScope::SessionRead)?;
        let request = request_context(ctx)?;
        let max_page_size = ctx.data_opt::<usize>().copied().unwrap_or(100);
        let repo = SessionRepositoryImpl::new(request.state.resources().db().clone());
        let current_session_oid = request.claims.session_oid;
        let user_oid = Uuid::from(request.claims.user_oid);
        let data_protector = request.state.services().data_protector().clone();
        let cursor_purpose = session_cursor_purpose(user_oid);

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
                let direction = if last.is_some() {
                    SessionPageDirection::Backward
                } else {
                    SessionPageDirection::Forward
                };
                let after = unprotect_session_cursor(
                    data_protector.as_ref(),
                    &cursor_purpose,
                    after.as_ref(),
                )
                .await?;
                let before = unprotect_session_cursor(
                    data_protector.as_ref(),
                    &cursor_purpose,
                    before.as_ref(),
                )
                .await?;
                let page = repo
                    .list_page_by_user_oid(user_oid, after, before, requested, direction)
                    .await
                    .map_err(internal_error)?;
                let cursor_plaintexts = page
                    .items
                    .iter()
                    .map(|item| {
                        SessionCursor::new(item.sort_key.last_active_at, item.sort_key.id)
                            .to_bytes()
                    })
                    .collect::<Vec<_>>();
                let protected_cursors = data_protector
                    .protect_many(&cursor_purpose, &cursor_plaintexts)
                    .await
                    .map_err(internal_error)?;
                let mut connection = Connection::new(page.has_previous_page, page.has_next_page);
                connection.edges.extend(
                    page.items
                        .into_iter()
                        .zip(
                            protected_cursors
                                .into_iter()
                                .map(ProtectedSessionCursor::new),
                        )
                        .map(|(item, cursor)| {
                            Edge::new(cursor, SessionNode::new(item.session, current_session_oid))
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
    async fn update_account_identifiers(
        &self,
        ctx: &Context<'_>,
        input: UpdateAccountIdentifiersInput,
    ) -> Result<UpdateProfilePayload> {
        require_scope(ctx, ApiScope::AccountUpdate)?;
        require_recent_authentication(ctx, None)?;
        let request = request_context(ctx)?;
        let patch = validate_account_identifiers(&input).map_err(|error| app_error(ctx, error))?;
        let repo = UserRepositoryImpl::new(request.state.resources().db().clone());
        let user = repo
            .update_identifiers(request.claims.user_oid, patch)
            .await
            .map_err(|error| account_repository_error(ctx, error))?
            .ok_or_else(|| Error::new("account not found"))?;
        Ok(UpdateProfilePayload {
            user: UserNode::from(user),
            client_mutation_id: input.client_mutation_id,
        })
    }

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
        require_recent_authentication(ctx, None)?;
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

    async fn begin_totp_enrollment(
        &self,
        ctx: &Context<'_>,
        client_mutation_id: Option<String>,
    ) -> Result<BeginTotpEnrollmentPayload> {
        require_scope(ctx, ApiScope::AccountUpdate)?;
        require_recent_authentication(ctx, None)?;
        let request = request_context(ctx)?;
        let issuer = request
            .state
            .services()
            .oidc()
            .issuer()
            .map_err(|error| app_error(ctx, error))?;
        let enrollment = request
            .state
            .services()
            .mfa()
            .begin_totp_enrollment(
                request.claims.user_oid,
                issuer.host_str().unwrap_or("Identity"),
                &request.user.email,
            )
            .await
            .map_err(|error| app_error(ctx, error))?;
        Ok(BeginTotpEnrollmentPayload {
            secret: enrollment.secret,
            otpauth_uri: enrollment.otpauth_uri,
            enrollment_token: enrollment.enrollment_token,
            client_mutation_id,
        })
    }

    async fn confirm_totp_enrollment(
        &self,
        ctx: &Context<'_>,
        input: ConfirmTotpEnrollmentInput,
    ) -> Result<RecoveryCodesPayload> {
        require_scope(ctx, ApiScope::AccountUpdate)?;
        require_recent_authentication(ctx, None)?;
        let request = request_context(ctx)?;
        let confirmed = request
            .state
            .services()
            .mfa()
            .confirm_totp_enrollment(
                request.claims.user_oid,
                &input.enrollment_token,
                &input.code,
            )
            .await
            .map_err(|error| app_error(ctx, error))?;
        Ok(RecoveryCodesPayload {
            recovery_codes: confirmed.recovery_codes,
            client_mutation_id: input.client_mutation_id,
        })
    }

    async fn disable_totp(
        &self,
        ctx: &Context<'_>,
        client_mutation_id: Option<String>,
    ) -> Result<TotpChangedPayload> {
        require_scope(ctx, ApiScope::AccountUpdate)?;
        require_recent_authentication(ctx, Some(identity_domain::auth::ACR_MFA))?;
        let request = request_context(ctx)?;
        request
            .state
            .services()
            .mfa()
            .disable_totp(request.claims.user_oid)
            .await
            .map_err(|error| app_error(ctx, error))?;
        Ok(TotpChangedPayload {
            changed: true,
            client_mutation_id,
        })
    }

    async fn regenerate_recovery_codes(
        &self,
        ctx: &Context<'_>,
        client_mutation_id: Option<String>,
    ) -> Result<RecoveryCodesPayload> {
        require_scope(ctx, ApiScope::AccountUpdate)?;
        require_recent_authentication(ctx, Some(identity_domain::auth::ACR_MFA))?;
        let request = request_context(ctx)?;
        let recovery_codes = request
            .state
            .services()
            .mfa()
            .regenerate_recovery_codes(request.claims.user_oid)
            .await
            .map_err(|error| app_error(ctx, error))?;
        Ok(RecoveryCodesPayload {
            recovery_codes,
            client_mutation_id,
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

pub struct AccountSecurity {
    totp_enabled: bool,
    recovery_codes_remaining: i32,
}

#[Object]
impl AccountSecurity {
    async fn totp_enabled(&self) -> bool {
        self.totp_enabled
    }

    async fn recovery_codes_remaining(&self) -> i32 {
        self.recovery_codes_remaining
    }
}

pub struct BeginTotpEnrollmentPayload {
    secret: String,
    otpauth_uri: String,
    enrollment_token: String,
    client_mutation_id: Option<String>,
}

#[Object]
impl BeginTotpEnrollmentPayload {
    async fn secret(&self) -> &str {
        &self.secret
    }

    async fn otpauth_uri(&self) -> &str {
        &self.otpauth_uri
    }

    async fn enrollment_token(&self) -> &str {
        &self.enrollment_token
    }

    async fn client_mutation_id(&self) -> Option<&str> {
        self.client_mutation_id.as_deref()
    }
}

#[derive(InputObject)]
pub struct ConfirmTotpEnrollmentInput {
    enrollment_token: String,
    code: String,
    client_mutation_id: Option<String>,
}

pub struct RecoveryCodesPayload {
    recovery_codes: Vec<String>,
    client_mutation_id: Option<String>,
}

#[Object]
impl RecoveryCodesPayload {
    async fn recovery_codes(&self) -> &[String] {
        &self.recovery_codes
    }

    async fn client_mutation_id(&self) -> Option<&str> {
        self.client_mutation_id.as_deref()
    }
}

pub struct TotpChangedPayload {
    changed: bool,
    client_mutation_id: Option<String>,
}

#[Object]
impl TotpChangedPayload {
    async fn changed(&self) -> bool {
        self.changed
    }

    async fn client_mutation_id(&self) -> Option<&str> {
        self.client_mutation_id.as_deref()
    }
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
            address_formatted: patch_value(self.address_formatted),
            address_street_address: patch_value(self.address_street_address),
            address_locality: patch_value(self.address_locality),
            address_region: patch_value(self.address_region),
            address_postal_code: patch_value(self.address_postal_code),
            address_country: patch_value(self.address_country),
        }
    }
}

#[derive(Clone, InputObject)]
pub struct UpdateAccountIdentifiersInput {
    pub username: String,
    pub email: String,
    pub client_mutation_id: Option<String>,
}

fn validate_account_identifiers(
    input: &UpdateAccountIdentifiersInput,
) -> std::result::Result<UserIdentifierPatch, AppError> {
    let mut error = AppError::from_code(AccountErrorCode::ValidationFailed);
    let username = match identity_domain::user::normalization::validate_username(&input.username) {
        Ok(normalized) => Some((input.username.trim().to_owned(), normalized)),
        Err(UsernameValidationError::Empty) => {
            error.push_field_error(
                "username",
                AppError::from_code(AccountErrorCode::UsernameRequired),
            );
            None
        }
        Err(UsernameValidationError::InvalidLength | UsernameValidationError::InvalidCharacter) => {
            error.push_field_error(
                "username",
                AppError::from_code(AccountErrorCode::UsernameInvalid),
            );
            None
        }
    };
    let email = match identity_domain::user::normalization::normalize_email(&input.email) {
        Ok(normalized) => Some((input.email.trim().to_owned(), normalized)),
        Err(EmailNormalizationError::Empty) => {
            error.push_field_error(
                "email",
                AppError::from_code(AccountErrorCode::EmailRequired),
            );
            None
        }
        Err(EmailNormalizationError::InvalidFormat | EmailNormalizationError::InvalidDomain) => {
            error.push_field_error("email", AppError::from_code(AccountErrorCode::EmailInvalid));
            None
        }
    };
    if error
        .validation()
        .is_some_and(|validation| !validation.is_empty())
    {
        Err(error)
    } else {
        Ok(UserIdentifierPatch { username, email })
    }
}

fn account_repository_error(ctx: &Context<'_>, error: UserRepositoryError) -> Error {
    match error {
        UserRepositoryError::UsernameExists => app_error(
            ctx,
            AppError::from_code(AccountErrorCode::UsernameExists).with_field("username"),
        ),
        UserRepositoryError::EmailExists => app_error(
            ctx,
            AppError::from_code(AccountErrorCode::EmailExists).with_field("email"),
        ),
        error => internal_error(error),
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

fn require_recent_authentication(ctx: &Context<'_>, required_acr: Option<&str>) -> Result<()> {
    let claims = &request_context(ctx)?.claims;
    let now = chrono::Utc::now().timestamp();
    if claims
        .auth_time
        .is_some_and(|auth_time| now.saturating_sub(auth_time) <= 300)
        && claims.acr.is_some()
        && required_acr.is_none_or(|required| claims.acr.as_deref() == Some(required))
    {
        Ok(())
    } else {
        Err(
            Error::new("recent authentication is required").extend_with(|_, extensions| {
                extensions.set("kind", "authorization_error");
                extensions.set("code", "FRESH_AUTHENTICATION_REQUIRED");
                if let Some(required_acr) = required_acr {
                    extensions.set("requiredAcr", required_acr);
                }
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

fn session_cursor_purpose(user_oid: Uuid) -> String {
    format!("graphql:session-cursor:v2:{user_oid}")
}

async fn unprotect_session_cursor(
    data_protector: &dyn DataProtector,
    purpose: &str,
    cursor: Option<&ProtectedSessionCursor>,
) -> Result<Option<SessionSortKey>> {
    use chrono::TimeZone as _;

    let Some(cursor) = cursor else {
        return Ok(None);
    };
    let plaintext = data_protector
        .unprotect(purpose, cursor.as_str())
        .await
        .map_err(|_| Error::new("invalid session cursor"))?;
    let cursor =
        SessionCursor::from_bytes(&plaintext).map_err(|_| Error::new("invalid session cursor"))?;
    if cursor.id <= 0 {
        return Err(Error::new("invalid session cursor"));
    }
    let last_active_at = chrono::Utc
        .timestamp_micros(cursor.last_active_micros)
        .single()
        .ok_or_else(|| Error::new("invalid session cursor"))?;
    Ok(Some(SessionSortKey {
        last_active_at,
        id: cursor.id,
    }))
}

#[cfg(test)]
mod tests {
    use super::{UpdateAccountIdentifiersInput, build_schema, validate_account_identifiers};

    #[test]
    fn schema_exposes_mfa_self_service_contract() {
        let sdl = build_schema(20, 1_000).sdl();

        for field in [
            "security: AccountSecurity!",
            "beginTotpEnrollment(",
            "confirmTotpEnrollment(",
            "disableTotp(",
            "regenerateRecoveryCodes(",
            "recoveryCodesRemaining: Int!",
        ] {
            assert!(sdl.contains(field), "schema is missing {field}");
        }
    }

    #[test]
    fn schema_exposes_identifier_updates_without_phone_management() {
        let sdl = build_schema(20, 1_000).sdl();

        assert!(sdl.contains("updateAccountIdentifiers("));
        assert!(sdl.contains("input UpdateAccountIdentifiersInput"));
        assert!(!sdl.contains("phoneNumber"));
    }

    #[test]
    fn identifier_validation_returns_both_field_errors() {
        let error = validate_account_identifiers(&UpdateAccountIdentifiersInput {
            username: "@".to_owned(),
            email: "invalid".to_owned(),
            client_mutation_id: None,
        })
        .unwrap_err();
        let fields = error.validation().unwrap().fields();

        assert_eq!(fields.len(), 2);
        assert_eq!(fields[0].field(), "username");
        assert_eq!(fields[0].code(), 15_002);
        assert_eq!(fields[1].field(), "email");
        assert_eq!(fields[1].code(), 15_004);
    }

    #[test]
    fn identifier_validation_normalizes_unique_keys_but_preserves_display_values() {
        let patch = validate_account_identifiers(&UpdateAccountIdentifiersInput {
            username: " Alice-01 ".to_owned(),
            email: "USER@例子.测试".to_owned(),
            client_mutation_id: None,
        })
        .unwrap();

        assert_eq!(
            patch.username,
            Some(("Alice-01".to_owned(), "alice-01".to_owned()))
        );
        assert_eq!(
            patch.email,
            Some((
                "USER@例子.测试".to_owned(),
                "user@xn--fsqu00a.xn--0zwm56d".to_owned()
            ))
        );
    }
}
