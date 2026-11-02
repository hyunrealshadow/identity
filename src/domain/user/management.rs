//! Management-facing user record.
//!
//! [`User`](crate::user::User) is the authentication/account model used across
//! existing flows. The management view uses the core `user.version` UUID as its
//! optimistic-lock token. Versions are never
//! counters and never reused.

use uuid::Uuid;

use crate::user::{User, UserOid};

/// Management record: the existing domain user plus its current UUID version.
#[derive(Debug, Clone)]
pub struct UserManagementRecord {
    pub user: User,
}

impl UserManagementRecord {
    #[must_use]
    pub fn new(user: User) -> Self {
        Self { user }
    }

    #[must_use]
    pub fn version(&self) -> Uuid {
        self.user.version
    }

    #[must_use]
    pub fn oid(&self) -> UserOid {
        self.user.oid
    }
}

#[cfg(test)]
mod tests {
    use chrono::Utc;
    use uuid::Uuid;

    use crate::user::{MfaMethod, User, UserOid};

    #[test]
    fn management_record_uses_the_core_user_version() {
        let version = Uuid::new_v4();
        let user = User {
            oid: UserOid(Uuid::new_v4()),
            version,
            email: "user@example.test".to_owned(),
            email_normalized: "user@example.test".to_owned(),
            name: "user".to_owned(),
            name_normalized: "user".to_owned(),
            given_name: None,
            family_name: None,
            middle_name: None,
            nickname: None,
            profile: None,
            picture: None,
            website: None,
            gender: None,
            birthdate: None,
            zoneinfo: None,
            locale: None,
            theme: None,
            preferred_mfa_method: MfaMethod::Passkey,
            email_verified: false,
            phone_number: None,
            phone_number_verified: None,
            address_formatted: None,
            address_street_address: None,
            address_locality: None,
            address_region: None,
            address_postal_code: None,
            address_country: None,
            failed_attempts: 0,
            enabled: true,
            locked: false,
            locked_until: None,
            created_at: Utc::now(),
            updated_at: None,
        };
        let record = super::UserManagementRecord::new(user.clone());
        assert_eq!(record.oid(), user.oid);
        assert_eq!(record.version(), version);
        assert_eq!(record.user.name, "user");
    }
}
