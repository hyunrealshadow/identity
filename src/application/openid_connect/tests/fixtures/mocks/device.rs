use chrono::{DateTime, Utc};
use identity_domain::client::model::ClientOid;
use identity_domain::client_authorization::{
    ClientAuthorization, DeviceAuthorizationApproval, DeviceAuthorizationRepository,
    DeviceAuthorizationRepositoryError, DeviceAuthorizationRequestData, DeviceConsumeOutcome,
    DevicePollOutcome, PreparedAuthorizationRecord,
};
use uuid::Uuid;

mockall::mock! {
    pub DeviceAuthorizationRepository {}

    #[async_trait::async_trait]
    impl DeviceAuthorizationRepository for DeviceAuthorizationRepository {
        async fn create_device_request(
            &self,
            client_oid: ClientOid,
            data: DeviceAuthorizationRequestData,
            expires_at: DateTime<Utc>,
        ) -> Result<ClientAuthorization, DeviceAuthorizationRepositoryError>;

        async fn find_device_request_by_oid(
            &self,
            oid: Uuid,
        ) -> Result<Option<ClientAuthorization>, DeviceAuthorizationRepositoryError>;

        async fn find_device_request_by_device_code_digest(
            &self,
            digest: &str,
        ) -> Result<Option<ClientAuthorization>, DeviceAuthorizationRepositoryError>;

        async fn find_active_device_request_by_user_code(
            &self,
            user_code: &str,
        ) -> Result<Option<ClientAuthorization>, DeviceAuthorizationRepositoryError>;

        async fn find_device_authorization_by_oid(
            &self,
            oid: Uuid,
        ) -> Result<Option<ClientAuthorization>, DeviceAuthorizationRepositoryError>;

        async fn record_device_poll(
            &self,
            request_oid: Uuid,
            polled_at: DateTime<Utc>,
        ) -> Result<DevicePollOutcome, DeviceAuthorizationRepositoryError>;

        async fn approve_device_request(
            &self,
            request_oid: Uuid,
            approval: DeviceAuthorizationApproval,
            decided_at: DateTime<Utc>,
        ) -> Result<Option<Uuid>, DeviceAuthorizationRepositoryError>;

        async fn deny_device_request(
            &self,
            request_oid: Uuid,
            user_oid: Uuid,
            decided_at: DateTime<Utc>,
        ) -> Result<bool, DeviceAuthorizationRepositoryError>;

        async fn consume_device_request_with_tokens(
            &self,
            request_oid: Uuid,
            records: Vec<PreparedAuthorizationRecord>,
            now: DateTime<Utc>,
        ) -> Result<DeviceConsumeOutcome, DeviceAuthorizationRepositoryError>;

        async fn revoke_device_authorization(
            &self,
            device_authorization_oid: Uuid,
            revoked_at: DateTime<Utc>,
        ) -> Result<bool, DeviceAuthorizationRepositoryError>;

        async fn revoke_device_authorizations_for_user(
            &self,
            user_oid: Uuid,
            revoked_at: DateTime<Utc>,
        ) -> Result<u64, DeviceAuthorizationRepositoryError>;

        async fn delete_expired_device_requests(
            &self,
            now: DateTime<Utc>,
        ) -> Result<u64, DeviceAuthorizationRepositoryError>;
    }
}
