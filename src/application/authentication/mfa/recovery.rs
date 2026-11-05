use super::*;

const RECOVERY_ENROLLMENT_PURPOSE: &str = "identity.mfa.recovery-enrollment.v1";

#[derive(Debug, Clone)]
pub struct RecoveryCodeEnrollment {
    pub recovery_codes: Vec<String>,
    pub enrollment_token: Option<String>,
}

#[derive(Serialize, Deserialize)]
struct PendingRecoveryCodeEnrollment {
    user_oid: UserOid,
    expires_at: DateTime<Utc>,
    credentials: Vec<RecoveryCodeCredentialData>,
}

impl MfaService {
    /// Prepare a batch for display before adding an MFA method. It is persisted
    /// together with the new credential, so cancelling enrollment changes nothing.
    pub async fn prepare_recovery_code_enrollment(
        &self,
        user_oid: UserOid,
    ) -> Result<RecoveryCodeEnrollment, AppError> {
        if self.status(user_oid).await?.recovery_codes_remaining > 0 {
            return Ok(RecoveryCodeEnrollment {
                recovery_codes: Vec::new(),
                enrollment_token: None,
            });
        }
        let (recovery_codes, credentials) = generate_recovery_codes();
        let pending = PendingRecoveryCodeEnrollment {
            user_oid,
            expires_at: Utc::now() + ENROLLMENT_LIFETIME,
            credentials,
        };
        let token = self
            .data_protector
            .protect(
                RECOVERY_ENROLLMENT_PURPOSE,
                &to_vec(&pending).map_err(AppError::internal)?,
            )
            .await?;
        Ok(RecoveryCodeEnrollment {
            recovery_codes,
            enrollment_token: Some(token),
        })
    }

    /// Resolve a protected account-bound batch, or require existing recovery
    /// codes. The credential repository rechecks the invariant under its lock.
    pub async fn registration_recovery_codes(
        &self,
        user_oid: UserOid,
        enrollment_token: Option<&str>,
    ) -> Result<Vec<RecoveryCodeCredentialData>, AppError> {
        let invalid = || AppError::from_code(AuthErrorCode::InvalidMfaEnrollment);
        let Some(token) = enrollment_token else {
            return if self.status(user_oid).await?.recovery_codes_remaining > 0 {
                Ok(Vec::new())
            } else {
                Err(invalid())
            };
        };
        let plaintext = self
            .data_protector
            .unprotect(RECOVERY_ENROLLMENT_PURPOSE, token)
            .await
            .map_err(|_| invalid())?;
        let pending: PendingRecoveryCodeEnrollment =
            from_slice(&plaintext).map_err(|_| invalid())?;
        if pending.user_oid != user_oid || pending.expires_at <= Utc::now() {
            return Err(invalid());
        }
        Ok(pending.credentials)
    }
}
