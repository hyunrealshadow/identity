use chrono::{DateTime, Utc};
use identity_domain::user::repository::{UserRepository, UserRepositoryError};
use identity_domain::user::{User, UserOid};

mockall::mock! {
    pub UserRepository {}

    #[async_trait::async_trait]
    impl UserRepository for UserRepository {
        async fn find_by_identifier(&self, identifier: &str)
            -> Result<User, UserRepositoryError>;
        async fn find_by_oid(&self, oid: UserOid)
            -> Result<Option<User>, UserRepositoryError>;
        async fn increment_failed_attempts(&self, user_oid: UserOid, lock_until: Option<DateTime<Utc>>)
            -> Result<(), UserRepositoryError>;
        async fn reset_failed_attempts(&self, user_oid: UserOid)
            -> Result<(), UserRepositoryError>;
    }
}

/// Creates a MockUserRepository that returns the given user for find_by_oid
/// and find_by_identifier.
pub fn user_repo_with(user: User) -> MockUserRepository {
    let mut mock = MockUserRepository::new();
    let u = user.clone();
    mock.expect_find_by_oid()
        .returning(move |oid| Ok((u.oid == oid).then(|| u.clone())));
    let u = user.clone();
    mock.expect_find_by_identifier()
        .returning(move |_| Ok(u.clone()));
    mock.expect_increment_failed_attempts()
        .returning(|_user_oid, _lock_until| Ok(()));
    mock.expect_reset_failed_attempts()
        .returning(|_user_oid| Ok(()));
    mock
}
