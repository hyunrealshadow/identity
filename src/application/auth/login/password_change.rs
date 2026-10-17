use super::{LoginService, PasswordChangeOutcome};
use crate::{
    auth::{
        password::{VerifyResult, run_password_hashing},
        session::revoke_other_sessions_with,
    },
    error::{
        AppError,
        codes::{auth::AuthErrorCode, common::CommonErrorCode},
    },
    observability::{BusinessEvent, EventValue},
    setting::PasswordHashSetting,
    user::{
        UserOid,
        model::{CredentialData, CredentialType},
    },
};
use chrono::Utc;
use identity_domain::auth::SessionOid;
use std::sync::Arc;
use uuid::Uuid;

impl LoginService {
    pub async fn change_password(
        &self,
        user_oid: UserOid,
        new_password: &str,
    ) -> Result<(), AppError> {
        if new_password.len() < 12 {
            return Err(
                AppError::from_code(CommonErrorCode::ValidationFailed).with_field_error(
                    "newPassword",
                    AppError::from_code(AuthErrorCode::PasswordTooShort),
                ),
            );
        }
        let credential = self
            .credential_repo
            .find_by_user_oid_and_type(user_oid, CredentialType::Password)
            .await?
            .into_iter()
            .next()
            .ok_or_else(|| AppError::from_code(AuthErrorCode::CredentialTypeUnsupported))?;
        let stored_password = match &credential.data {
            CredentialData::Password(password) => password.clone(),
            _ => {
                return Err(AppError::from_code(
                    AuthErrorCode::CredentialTypeUnsupported,
                ));
            }
        };
        let options = self.settings.snapshot().get::<PasswordHashSetting>();
        let hasher = Arc::clone(&self.password_hasher);
        let new_password_to_verify = new_password.to_owned();
        let verify_options = options.clone();
        let verified = run_password_hashing(move || {
            hasher.verify(&new_password_to_verify, &stored_password, &verify_options)
        })
        .await?;
        if verified != VerifyResult::Failure {
            return Err(
                AppError::from_code(CommonErrorCode::ValidationFailed).with_field_error(
                    "newPassword",
                    AppError::from_code(AuthErrorCode::PasswordUnchanged),
                ),
            );
        }
        let hasher = Arc::clone(&self.password_hasher);
        let new_password = new_password.to_owned();
        let password = run_password_hashing(move || hasher.hash(&new_password, &options)).await?;
        self.credential_repo
            .update_password_by_oid(credential.oid, &password)
            .await?;
        self.events.emit(
            BusinessEvent::audit("account.credential.changed")
                .outcome("success")
                .attribute(
                    "credential_oid",
                    EventValue::Text(credential.oid.0.to_string()),
                )
                .attribute(
                    "user_oid",
                    EventValue::Pseudonymized {
                        purpose: "user_oid",
                        value: Uuid::from(user_oid).to_string(),
                    },
                )
                .attribute("change_category", EventValue::Text("password".to_owned())),
        );
        Ok(())
    }

    /// Change the password and revoke every other session of the account.
    ///
    /// The outcome distinguishes the completed password change from partial
    /// session revocation failures so callers never report that the password
    /// was not changed when it was, and audit events can describe both steps.
    #[tracing::instrument(skip_all, name = "account.password.change")]
    pub async fn change_password_with_session_revocation(
        &self,
        user_oid: UserOid,
        new_password: &str,
        current_session: SessionOid,
    ) -> Result<PasswordChangeOutcome, AppError> {
        self.change_password(user_oid, new_password).await?;
        let revocation = revoke_other_sessions_with(
            self.session_repo.as_ref(),
            Uuid::from(user_oid),
            current_session,
        )
        .await?;
        let revoked_device_authorizations = self
            .revoke_device_authorizations(Uuid::from(user_oid))
            .await?;
        let mut event = BusinessEvent::audit("account.sessions_revoked")
            .outcome("success")
            .attribute(
                "revoked_sessions",
                EventValue::Integer(i64::from(revocation.revoked)),
            )
            .attribute(
                "revoked_device_authorizations",
                EventValue::Integer(i64::from(revoked_device_authorizations)),
            )
            .attribute(
                "user_oid",
                EventValue::Pseudonymized {
                    purpose: "user_oid",
                    value: Uuid::from(user_oid).to_string(),
                },
            );
        if revocation.failure_count() > 0 {
            event = event.outcome("partial");
        }
        self.events.emit(event);

        Ok(PasswordChangeOutcome {
            password_changed: true,
            revoked_other_sessions: revocation.revoked,
            session_revocation_failures: revocation.failure_count(),
        })
    }

    /// Withdraws every device authorization of an account. Browser logouts do
    /// not call this: a device relation outlives the session that approved it
    /// (ADR 0004); only account level security actions end it.
    async fn revoke_device_authorizations(&self, user_oid: Uuid) -> Result<u32, AppError> {
        let Some(device_repo) = &self.device_repo else {
            return Ok(0);
        };

        let revoked = device_repo
            .revoke_device_authorizations_for_user(user_oid, Utc::now())
            .await
            .map_err(AppError::map_source(
                AuthErrorCode::DeviceAuthorizationRevocationFailed,
            ))?;

        Ok(u32::try_from(revoked).unwrap_or(u32::MAX))
    }
}
