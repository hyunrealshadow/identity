use super::AuthorizeService;
use crate::error::codes::{auth::AuthErrorCode, authorize_http::AuthorizeHttpErrorCode};
use crate::error::{AppError, codes::authorize::AuthorizeErrorCode};
use chrono::{DateTime, Utc};
use identity_domain::{
    auth::{LoginStatus, SessionOid, model::Login},
    client_authorization::{SelectionSource, StoredAuthorizationRequest},
    openid_connect::OpenIdConnectClient,
};
use uuid::Uuid;

#[derive(Debug)]
pub struct ContinueContext {
    pub login: Login,
    pub stored: StoredAuthorizationRequest,
    pub client: OpenIdConnectClient,
    pub expires_at: DateTime<Utc>,
    pub completed_at: Option<DateTime<Utc>>,
}

impl AuthorizeService {
    pub async fn create_login_flow(
        &self,
        client_oid: Uuid,
        authorization_request_id: Uuid,
        requested_acr: Option<&str>,
    ) -> Result<String, AppError> {
        let login = self
            .login_repo
            .create_pending(client_oid, authorization_request_id, requested_acr)
            .await
            .map_err(AppError::map_source(AuthorizeErrorCode::StoreLoginFailed))?;

        self.encrypt_login_id(login.oid).await
    }

    /// Roll the same unfinished login back to identifier entry when the user
    /// chooses a different account before authentication completes.
    pub async fn switch_login_account(
        &self,
        protected_login_oid: &str,
    ) -> Result<String, AppError> {
        let context = self
            .load_continue_context_by_login(protected_login_oid)
            .await?;
        if context.expires_at <= Utc::now() || context.completed_at.is_some() {
            return Err(AppError::from_code(
                AuthorizeHttpErrorCode::ContinueInteractionUnavailable,
            ));
        }
        if context.stored.interaction.selection_source == Some(SelectionSource::Reauthentication)
            || !matches!(
                context.login.status,
                LoginStatus::IDENTIFIER_VERIFIED | LoginStatus::MFA_REQUIRED
            )
        {
            return Err(AppError::from_code(AuthErrorCode::InvalidLoginState));
        }

        self.login_repo
            .reset_identity(context.login.oid)
            .await
            .map_err(AppError::map_source(AuthorizeErrorCode::StoreLoginFailed))?;
        Ok(protected_login_oid.to_owned())
    }

    /// Create a fresh login record for an authorization interaction whose
    /// credential challenge can no longer be continued.
    ///
    /// The authorization request remains the source of truth. In particular,
    /// a forced reauthentication keeps its selected subject and session so a
    /// restart cannot turn into an account switch.
    pub async fn restart_login_flow(&self, protected_login_oid: &str) -> Result<String, AppError> {
        let context = self
            .load_continue_context_by_login(protected_login_oid)
            .await?;
        if context.expires_at <= Utc::now() || context.completed_at.is_some() {
            return Err(AppError::from_code(
                AuthorizeHttpErrorCode::ContinueInteractionUnavailable,
            ));
        }
        if context.login.status != LoginStatus::EXPIRED {
            return Err(AppError::from_code(AuthErrorCode::InvalidLoginState));
        }

        let reauthentication = if context.stored.interaction.selection_source
            == Some(SelectionSource::Reauthentication)
        {
            let user_oid = context
                .stored
                .interaction
                .selected_user_oid
                .as_deref()
                .and_then(|value| Uuid::parse_str(value).ok())
                .ok_or_else(Self::interaction_conflict)?;
            let session_oid = context
                .stored
                .interaction
                .selected_session_oid
                .ok_or_else(Self::interaction_conflict)?;
            Some((user_oid, session_oid))
        } else {
            None
        };

        self.create_replacement_login(&context, reauthentication)
            .await
    }

    async fn create_replacement_login(
        &self,
        context: &ContinueContext,
        reauthentication: Option<(Uuid, SessionOid)>,
    ) -> Result<String, AppError> {
        let login = self
            .login_repo
            .create_pending(
                context.login.client_oid,
                context.login.client_authorization_oid,
                context.login.requested_acr.as_deref(),
            )
            .await
            .map_err(AppError::map_source(AuthorizeErrorCode::StoreLoginFailed))?;

        if let Some((user_oid, session_oid)) = reauthentication {
            self.login_repo
                .bind_user(login.oid, user_oid)
                .await
                .map_err(AppError::map_source(AuthorizeErrorCode::StoreLoginFailed))?;
            self.login_repo
                .bind_session(login.oid, session_oid)
                .await
                .map_err(AppError::map_source(AuthorizeErrorCode::StoreLoginFailed))?;
        }
        self.encrypt_login_id(login.oid).await
    }

    pub async fn load_continue_context_by_login(
        &self,
        protected_login_oid: &str,
    ) -> Result<ContinueContext, AppError> {
        let login = self.load_login_by_protected_id(protected_login_oid).await?;
        let record = self
            .load_authorization_request_record(login.client_authorization_oid)
            .await?;
        let expires_at = record.expires_at;
        let completed_at = record.completed_at;
        let stored = Self::stored_authorization_request(record.data)?;
        let client_id = Uuid::parse_str(&stored.request.client_id).map_err(
            AppError::map_source(AuthorizeErrorCode::StoredClientIdInvalid),
        )?;
        let client = self
            .client_repo
            .find_by_oid(client_id)
            .await
            .map_err(AppError::map_source(AuthorizeErrorCode::ClientLookupFailed))?
            .ok_or_else(|| AppError::from_code(AuthorizeErrorCode::ClientNotFound))?;

        Ok(ContinueContext {
            login,
            stored,
            client,
            expires_at,
            completed_at,
        })
    }

    pub async fn record_selection_by_login(
        &self,
        protected_login_oid: &str,
        session_oid: SessionOid,
        user_oid: Uuid,
        protected_session_id: Option<String>,
        source: SelectionSource,
    ) -> Result<(), AppError> {
        let login = self.load_login_by_protected_id(protected_login_oid).await?;
        let stored = self
            .load_stored_authorization_request(login.client_authorization_oid)
            .await?;
        let selected_user_oid = user_oid.to_string();
        let is_reauthentication =
            stored.interaction.selection_source == Some(SelectionSource::Reauthentication);
        if is_reauthentication
            && (stored.interaction.selected_session_oid != Some(session_oid)
                || stored.interaction.selected_user_oid.as_deref()
                    != Some(selected_user_oid.as_str()))
        {
            return Err(Self::interaction_conflict());
        }
        let source = if is_reauthentication {
            SelectionSource::Reauthentication
        } else {
            source
        };
        self.record_authorization_selection(
            login.client_authorization_oid,
            session_oid,
            user_oid,
            protected_session_id,
            source,
        )
        .await?;
        // The initial forced-login selection binds the existing subject so the
        // challenge page can authenticate it.  Controllers record the selected
        // session again after a successful challenge; do not downgrade that
        // completed login back to `identifier_verified` on the second write.
        if source == SelectionSource::Reauthentication && login.status != LoginStatus::AUTHENTICATED
        {
            self.login_repo
                .bind_user(login.oid, user_oid)
                .await
                .map_err(AppError::map_source(AuthorizeErrorCode::StoreLoginFailed))?;
        }
        self.login_repo
            .bind_session(login.oid, session_oid)
            .await
            .map_err(AppError::map_source(AuthorizeErrorCode::StoreLoginFailed))
    }

    pub async fn record_authorization_selection(
        &self,
        authorization_request_id: Uuid,
        session_oid: SessionOid,
        user_oid: Uuid,
        protected_session_id: Option<String>,
        source: SelectionSource,
    ) -> Result<(), AppError> {
        let updated = self
            .client_authorization_repo
            .update_authorization_request_selection(
                authorization_request_id,
                session_oid,
                user_oid,
                protected_session_id,
                source,
            )
            .await
            .map_err(AppError::map_source(AuthorizeErrorCode::StoreRequestFailed))?;

        if !updated {
            return Err(Self::interaction_conflict());
        }

        Ok(())
    }

    pub async fn load_login_by_protected_id(
        &self,
        protected_login_id: &str,
    ) -> Result<Login, AppError> {
        let login_oid = self.decrypt_login_id(protected_login_id).await?;

        self.login_repo
            .find_by_oid(login_oid)
            .await
            .map_err(AppError::map_source(AuthorizeErrorCode::LoadLoginFailed))?
            .ok_or_else(|| AppError::from_code(AuthorizeErrorCode::LoginNotFound))
    }
}
