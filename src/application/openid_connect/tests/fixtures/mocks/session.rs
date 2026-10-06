use chrono::{DateTime, Utc};
use identity_domain::auth::{
    SessionOid,
    model::{ActiveSession, Session},
    repository::{
        CreateSessionInput, SessionPage, SessionPageDirection, SessionRepository,
        SessionRepositoryError, SessionSortKey,
    },
};
use mockall::mock;
use uuid::Uuid;

mock! {
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
        async fn create(&self, input: CreateSessionInput)
            -> Result<Session, SessionRepositoryError>;
        async fn reauthenticate_by_oid(
            &self,
            oid: SessionOid,
            expected_user_oid: Uuid,
            acr: &str,
            acr_expires_at: DateTime<Utc>,
            amr: &[String],
        ) -> Result<Session, SessionRepositoryError>;
        async fn touch_active_by_oid(
            &self,
            oid: SessionOid,
        ) -> Result<bool, SessionRepositoryError>;
        async fn revoke_by_oid(
            &self,
            oid: SessionOid,
            revoked_at: DateTime<Utc>,
        ) -> Result<Option<Session>, SessionRepositoryError>;
        async fn list_by_user_oid(
            &self,
            user_oid: Uuid,
        ) -> Result<Vec<Session>, SessionRepositoryError>;
        async fn list_active_page_by_user_oid(
            &self,
            user_oid: Uuid,
            after: Option<SessionSortKey>,
            before: Option<SessionSortKey>,
            limit: usize,
            direction: SessionPageDirection,
        ) -> Result<SessionPage, SessionRepositoryError>;
    }
}
