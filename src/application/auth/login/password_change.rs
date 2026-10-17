use super::{LoginService, PasswordChangeOutcome};
use crate::{
    auth::password::{VerifyResult, run_password_hashing},
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
use identity_domain::auth::SessionOid;
use std::sync::Arc;
use uuid::Uuid;

impl LoginService {
    async fn prepare_password_change(
        &self,
        user_oid: UserOid,
        new_password: &str,
    ) -> Result<
        (
            crate::user::UserCredentialOid,
            crate::user::Password,
            crate::user::Password,
        ),
        AppError,
    > {
        let user = self.get_user(user_oid).await?;
        super::super::password_policy::validate_password(
            new_password,
            &[&user.name, &user.email],
            "newPassword",
        )?;
        if self.breach_checker.is_breached(new_password).await? {
            return Err(super::super::password_policy::password_error(
                AuthErrorCode::PasswordBreached,
                "newPassword",
            ));
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
        let verify_stored = stored_password.clone();
        let verified = run_password_hashing(move || {
            hasher.verify(&new_password_to_verify, &verify_stored, &verify_options)
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
        Ok((credential.oid, stored_password, password))
    }

    /// Change a password without retaining any existing browser session.
    pub async fn change_password(
        &self,
        user_oid: UserOid,
        new_password: &str,
    ) -> Result<(), AppError> {
        let (credential, expected, password) =
            self.prepare_password_change(user_oid, new_password).await?;
        self.credential_repo
            .change_password_and_revoke(user_oid, credential, &expected, &password, None)
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
        let (credential, expected, password) =
            self.prepare_password_change(user_oid, new_password).await?;
        let revoked = self
            .credential_repo
            .change_password_and_revoke(
                user_oid,
                credential,
                &expected,
                &password,
                Some(current_session),
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
}
