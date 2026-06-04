use chrono::{DateTime, Utc};
use identity_domain::auth::SessionOid;
use identity_domain::auth::model::{ActiveSession, Session};
use identity_domain::auth::repository::{SessionRepository, SessionRepositoryError};

mockall::mock! {
    pub SessionRepository {}

    #[async_trait::async_trait]
    impl SessionRepository for SessionRepository {
        async fn find_by_oid(
            &self,
            oid: SessionOid,
        ) -> Result<Option<Session>, SessionRepositoryError>;
        async fn find_active_accounts_by_oids(
            &self,
            oids: &[SessionOid],
        ) -> Result<Vec<ActiveSession>, SessionRepositoryError>;
        async fn create(
            &self,
            user_oid: uuid::Uuid,
            device_name: Option<String>,
            device_type: Option<String>,
            os_name: Option<String>,
            os_version: Option<String>,
            browser_name: Option<String>,
            browser_version: Option<String>,
            user_agent: Option<String>,
            ip_address: Option<String>,
            expires_at: Option<DateTime<Utc>>,
            acr: Option<String>,
            acr_expires_at: Option<DateTime<Utc>>,
        ) -> Result<Session, SessionRepositoryError>;
        async fn touch_by_oid(
            &self,
            oid: SessionOid,
        ) -> Result<(), SessionRepositoryError>;
        async fn revoke_by_oid(
            &self,
            oid: SessionOid,
            revoked_at: DateTime<Utc>,
        ) -> Result<Option<Session>, SessionRepositoryError>;
    }
}
