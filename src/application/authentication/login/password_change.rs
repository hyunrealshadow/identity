use super::{
    super::password_policy, ChallengeOutcome, LoginService, PasswordChangeOutcome, SessionContext,
};
use crate::{
    authentication::password::{VerifyResult, run_password_hashing},
    error::{
        AppError,
        codes::{auth, common},
    },
    observability::{BusinessEvent, EventValue},
    setting::{PasswordHashSetting, PasswordHistoryCountSetting, PasswordMaxAgeDaysSetting},
    user::{
        Password, RequiredAction, UserCredentialOid, UserOid,
        model::{CredentialData, CredentialType},
        repository::{PasswordReplacement, PasswordReplacementKind},
    },
};
use chrono::{Duration, Utc};
use identity_domain::auth::{AuthenticationContextClass, LoginStatus, SessionOid};
use std::sync::Arc;
use tracing::error;
use uuid::Uuid;

/// A new password that passed the policy, hashed and ready to replace the
/// current one.
pub(super) struct PreparedPassword {
    credential: UserCredentialOid,
    expected: Password,
    password: Password,
    /// Replaced hashes to keep for the history check.
    keep_history: u32,
}

impl PreparedPassword {
    pub(super) fn replacement(&self, kind: PasswordReplacementKind) -> PasswordReplacement {
        PasswordReplacement {
            kind,
            keep_history: self.keep_history,
        }
    }
}

impl LoginService {
    /// Check `new_password` against the password policy, the current password
    /// and the recent ones the history setting covers, then hash it.
    pub(super) async fn prepare_password_change(
        &self,
        user_oid: UserOid,
        new_password: &str,
    ) -> Result<PreparedPassword, AppError> {
        let user = self.get_user(user_oid).await?;
        password_policy::validate_password(
            new_password,
            &[&user.name, &user.email],
            "newPassword",
        )?;
        let snapshot = self.settings.snapshot();
        password_policy::validate_breached_password(
            self.breach_checker.as_ref(),
            &snapshot,
            new_password,
            "newPassword",
        )
        .await?;
        let credential = self
            .credential_repo
            .find_by_user_oid_and_type(user_oid, CredentialType::Password)
            .await?
            .into_iter()
            .next()
            .ok_or_else(|| auth::error::CredentialTypeUnsupported::new("password"))?;
        let stored_password = match &credential.data {
            CredentialData::Password(password) => password.clone(),
            _ => {
                return Err(auth::error::CredentialTypeUnsupported::new("password").into());
            }
        };
        let options = snapshot.get::<PasswordHashSetting>();
        if self
            .matches_password(new_password, &stored_password, &options)
            .await?
        {
            return Err(common::error::ValidationFailed
                .with_field_error("newPassword", auth::error::PasswordUnchanged));
        }
        let history_count = snapshot.get::<PasswordHistoryCountSetting>();
        let keep_history = history_count.saturating_sub(1);
        for previous in self
            .credential_repo
            .password_history(user_oid, keep_history)
            .await?
        {
            if self
                .matches_password(new_password, &previous, &options)
                .await?
            {
                return Err(common::error::ValidationFailed.with_field_error(
                    "newPassword",
                    auth::error::PasswordReused::new(history_count),
                ));
            }
        }
        let hasher = Arc::clone(&self.password_hasher);
        let new_password = new_password.to_owned();
        let hash_options = options.clone();
        let password =
            run_password_hashing(move || hasher.hash(&new_password, &hash_options)).await?;
        Ok(PreparedPassword {
            credential: credential.oid,
            expected: stored_password,
            password,
            keep_history,
        })
    }

    async fn matches_password(
        &self,
        candidate: &str,
        stored: &Password,
        options: &crate::authentication::password::HashOptions,
    ) -> Result<bool, AppError> {
        let hasher = Arc::clone(&self.password_hasher);
        let candidate = candidate.to_owned();
        let stored = stored.clone();
        let options = options.clone();
        let verified =
            run_password_hashing(move || hasher.verify(&candidate, &stored, &options)).await?;
        Ok(verified != VerifyResult::Failure)
    }

    pub(super) async fn replace_prepared_password(
        &self,
        user_oid: UserOid,
        prepared: &PreparedPassword,
        kind: PasswordReplacementKind,
    ) -> Result<u32, AppError> {
        Ok(self
            .credential_repo
            .replace_password(
                user_oid,
                prepared.credential,
                &prepared.expected,
                &prepared.password,
                prepared.replacement(kind),
            )
            .await?)
    }

    /// Whether the account must replace its password before a sign-in
    /// finishes: an administrator required it, or it is older than the
    /// password expiry allows. Accounts without a password never need to.
    pub(super) async fn password_change_due(&self, user_oid: UserOid) -> Result<bool, AppError> {
        let Some(set_at) = self.credential_repo.password_set_at(user_oid).await? else {
            return Ok(false);
        };
        if self
            .get_user(user_oid)
            .await?
            .required_actions
            .contains(&RequiredAction::ChangePassword)
        {
            return Ok(true);
        }
        let max_age_days = self.settings.snapshot().get::<PasswordMaxAgeDaysSetting>();
        Ok(max_age_days > 0 && set_at + Duration::days(i64::from(max_age_days)) <= Utc::now())
    }

    /// Change a password without retaining any existing browser session.
    pub async fn change_password(
        &self,
        user_oid: UserOid,
        new_password: &str,
    ) -> Result<(), AppError> {
        let prepared = self.prepare_password_change(user_oid, new_password).await?;
        self.replace_prepared_password(
            user_oid,
            &prepared,
            PasswordReplacementKind::Change { keep: None },
        )
        .await?;
        Ok(())
    }

    /// Change the password and revoke every other session of the account.
    ///
    /// Password, other sessions and dependent authorizations change atomically.
    /// Any persistence or audit failure leaves the original credentials intact.
    #[tracing::instrument(skip_all, name = "account.password.change")]
    pub async fn change_password_with_session_revocation(
        &self,
        user_oid: UserOid,
        new_password: &str,
        current_session: SessionOid,
    ) -> Result<PasswordChangeOutcome, AppError> {
        let prepared = self.prepare_password_change(user_oid, new_password).await?;
        let revoked = self
            .replace_prepared_password(
                user_oid,
                &prepared,
                PasswordReplacementKind::Change {
                    keep: Some(current_session),
                },
            )
            .await?;
        let event = BusinessEvent::audit("account.sessions_revoked")
            .outcome("success")
            .attribute("revoked_sessions", EventValue::Integer(i64::from(revoked)))
            .attribute(
                "user_oid",
                EventValue::Pseudonymized {
                    purpose: "user_oid",
                    value: Uuid::from(user_oid).to_string(),
                },
            );
        self.events.emit(event);

        Ok(PasswordChangeOutcome {
            password_changed: true,
            revoked_other_sessions: revoked,
            session_revocation_failures: 0,
        })
    }

    /// Hold a login whose factors are all verified at the password change
    /// its account requires, keeping what it established for when it finishes.
    pub(super) async fn require_password_change(
        &self,
        login: &identity_domain::auth::model::Login,
        acr: AuthenticationContextClass,
        amr: &[String],
    ) -> Result<(), AppError> {
        self.login_repo.record_amr(login.oid, amr).await?;
        self.login_repo
            .update_status(
                login.oid,
                LoginStatus::PASSWORD_CHANGE_REQUIRED,
                None,
                Some(acr),
            )
            .await?;
        Ok(())
    }

    /// Replace the password a sign-in requires, then finish that sign-in.
    ///
    /// Every other session of the account ends with the change, as with any
    /// password change; the one this login reauthenticates is kept.
    #[tracing::instrument(skip_all, name = "authentication.password_change.required")]
    pub async fn complete_required_password_change(
        &self,
        login_oid: Uuid,
        new_password: &str,
        ctx: SessionContext,
    ) -> Result<ChallengeOutcome, AppError> {
        let login = self.get(login_oid).await?;
        if login.expires_at <= Utc::now() {
            return Err(auth::error::LoginExpired.into());
        }
        if login.status != LoginStatus::PASSWORD_CHANGE_REQUIRED {
            return Err(auth::error::InvalidLoginState.into());
        }
        let (Some(user_oid), Some(acr)) = (login.user_oid, login.acr) else {
            return Err(auth::error::InvalidLoginState.into());
        };
        let user = self.get_user(user_oid.into()).await?;
        self.ensure_user_can_authenticate(&user).await?;
        let prepared = self.prepare_password_change(user.oid, new_password).await?;
        self.replace_prepared_password(
            user.oid,
            &prepared,
            PasswordReplacementKind::Required {
                login: login.oid,
                keep: login.session_oid,
            },
        )
        .await?;
        let login = self.get(login_oid).await?;
        let amr = login.amr.clone();
        let session = self
            .complete_session(&login, user_oid, ctx, acr, &amr)
            .await?;
        if let Err(e) = self
            .login_repo
            .update_status(
                login.oid,
                LoginStatus::AUTHENTICATED,
                Some(session.oid),
                Some(acr),
            )
            .await
        {
            error!(error = %e, "failed to update login status to authenticated");
        }
        Ok(ChallengeOutcome::Authenticated {
            login,
            session: Box::new(session),
        })
    }
}
