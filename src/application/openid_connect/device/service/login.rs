//! Binding a device verification interaction to an authenticated browser login.

use super::{
    DeviceAuthorizationService,
    verification::{
        DeviceVerificationDecision, DeviceVerificationDescription, DeviceVerificationUser,
        description, request_data, verification_status,
    },
};
use crate::error::{AppError, codes::device};
use chrono::Utc;
use identity_domain::{
    auth::{LoginStatus, SessionOid, model::Login},
    client_authorization::ClientAuthorization,
};
use uuid::Uuid;

impl DeviceAuthorizationService {
    /// Resolve a device login without interpreting it as an OAuth authorization request.
    pub async fn login_request(
        &self,
        login: &Login,
    ) -> Result<Option<ClientAuthorization>, AppError> {
        self.device_repo
            .find_device_request_by_oid(login.client_authorization_oid)
            .await
            .map_err(device::error::LoadRequestFailed::map_source())
    }

    pub async fn begin_verification(&self, user_code: &str) -> Result<(Uuid, Uuid), AppError> {
        let record = self.resolve_verification(user_code).await?;
        let data = request_data(&record)?;
        if record.expires_at <= Utc::now() {
            return Err(device::error::RequestExpired.into_error());
        }
        if !data.is_pending() || data.claimed_login_oid.is_some() {
            return Err(device::error::UserCodeNotFound.into_error());
        }
        Ok((record.client_oid, record.oid))
    }

    pub async fn complete_login(
        &self,
        login: &Login,
        session_oid: SessionOid,
    ) -> Result<(), AppError> {
        if !self
            .device_repo
            .claim_device_request(
                login.client_authorization_oid,
                login.oid,
                session_oid,
                Utc::now(),
            )
            .await
            .map_err(device::error::StoreDecisionFailed::map_source())?
        {
            return Err(device::error::UserCodeNotFound.into_error());
        }
        Ok(())
    }

    async fn bound_request(&self, login: &Login) -> Result<ClientAuthorization, AppError> {
        let record = self
            .login_request(login)
            .await?
            .ok_or_else(|| device::error::UserCodeNotFound.into_error())?;
        let data = request_data(&record)?;
        if data.claimed_login_oid != Some(login.oid)
            || login.session_oid.is_none()
            || login.status != LoginStatus::AUTHENTICATED
        {
            return Err(device::error::VerificationLoginRequired.into_error());
        }
        if record.revoked_at.is_some() || record.expires_at <= Utc::now() {
            return Err(device::error::RequestExpired.into_error());
        }
        Ok(record)
    }

    pub async fn describe_login(
        &self,
        login: &Login,
    ) -> Result<DeviceVerificationDescription, AppError> {
        let record = self.bound_request(login).await?;
        let client = self.load_client(record.client_oid).await?;
        Ok(description(
            &client,
            &request_data(&record)?,
            verification_status(&record, Utc::now()),
        ))
    }

    pub async fn decide_login(
        &self,
        login: &Login,
        user: &DeviceVerificationUser,
        decision: DeviceVerificationDecision,
    ) -> Result<(), AppError> {
        let record = self.bound_request(login).await?;
        if login.user_oid != Some(user.user_oid) {
            return Err(device::error::VerificationLoginRequired.into_error());
        }
        self.record_decision(&record, &request_data(&record)?, user, decision)
            .await
    }
}
