//! User groups, memberships and group-role relations.
//!
//! A group is a container for role authority. It never owns permissions
//! directly, never nests another group and never grants inheritance. Memberships
//! and group-role relations have independent identities and UUID versions: a
//! removed relation is tombstoned and a later regrant must use a fresh OID
//! instead of reviving the old record.
//!
//! Built-in group definitions (identity, metadata, state and role set) are
//! immutable at runtime. Their user membership remains manageable by an actor
//! that holds the relevant group permission and stays within its delegation
//! ceiling.

use std::collections::BTreeSet;

use chrono::{DateTime, Utc};

use crate::{
    authorization::ids::AuthorizationVersion,
    rbac::{
        ids::{GroupMembershipOid, GroupOid, GroupRoleOid, RoleOid},
        metadata::{LocalizedMetadata, LocalizedText, canonicalize_locale},
    },
    user::UserOid,
};

pub const MAX_GROUP_NAME_LENGTH: usize = 256;
pub const MAX_GROUP_DESCRIPTION_LENGTH: usize = 1_024;
pub const MAX_GROUP_LOCALE_LENGTH: usize = 35;
pub const MAX_GROUP_TEXT_ENTRIES: usize = 20;
pub const MAX_GROUP_REASON_LENGTH: usize = 1_000;

/// Independent default text and optional translations; no default locale is stored.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Group {
    pub oid: GroupOid,
    pub built_in: bool,
    pub name: String,
    pub description: String,
    pub metadata: LocalizedMetadata,
    pub enabled: bool,
    pub version: AuthorizationVersion,
    pub created_at: DateTime<Utc>,
    pub updated_at: Option<DateTime<Utc>>,
}

impl Group {
    pub fn new(
        oid: GroupOid,
        name: String,
        description: String,
        metadata: LocalizedMetadata,
        created_at: DateTime<Utc>,
    ) -> Result<Self, GroupValidationError> {
        validate_group_metadata(&metadata)?;
        let name = validate_group_default(&name, true)?;
        let description = validate_group_default(&description, false)?;
        Ok(Self {
            oid,
            built_in: false,
            name,
            description,
            metadata,
            enabled: true,
            version: AuthorizationVersion::fresh(),
            created_at,
            updated_at: None,
        })
    }

    /// Trusted seed/install constructor for a built-in definition. Runtime
    /// callers never receive this path.
    pub fn built_in(
        oid: GroupOid,
        name: String,
        description: String,
        metadata: LocalizedMetadata,
        created_at: DateTime<Utc>,
    ) -> Result<Self, GroupValidationError> {
        let mut group = Self::new(oid, name, description, metadata, created_at)?;
        group.built_in = true;
        Ok(group)
    }

    #[must_use]
    pub fn is_built_in(&self) -> bool {
        self.built_in
    }

    pub fn ensure_definition_mutable(&self) -> Result<(), GroupValidationError> {
        if self.built_in {
            return Err(GroupValidationError::BuiltInDefinition);
        }
        Ok(())
    }

    /// Metadata-only edit. The row version rotates for optimistic concurrency;
    /// display changes do not withdraw an existing authorization.
    pub fn update_metadata(
        &mut self,
        metadata: Option<LocalizedMetadata>,
        now: DateTime<Utc>,
    ) -> Result<(), GroupValidationError> {
        self.ensure_definition_mutable()?;
        if let Some(metadata) = metadata {
            validate_group_metadata(&metadata)?;
            self.metadata = metadata;
        }
        self.version = AuthorizationVersion::fresh();
        self.updated_at = Some(now);
        Ok(())
    }

    /// Enable/disable is an authorization change and advances the group version.
    pub fn set_enabled(
        &mut self,
        enabled: bool,
        now: DateTime<Utc>,
    ) -> Result<bool, GroupValidationError> {
        self.ensure_definition_mutable()?;
        if self.enabled == enabled {
            return Ok(false);
        }
        self.enabled = enabled;
        self.version = AuthorizationVersion::fresh();
        self.updated_at = Some(now);
        Ok(true)
    }

    /// Advance the group authorization version for a relation change.
    pub fn advance_authorization(
        &mut self,
        now: DateTime<Utc>,
    ) -> Result<(), GroupValidationError> {
        self.version = AuthorizationVersion::fresh();
        self.updated_at = Some(now);
        Ok(())
    }
}

/// Explicit user membership in a group.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GroupMembership {
    pub oid: GroupMembershipOid,
    pub group_oid: GroupOid,
    pub user_oid: UserOid,
    pub granted_by_user_oid: Option<UserOid>,
    pub reason: String,
    pub enabled: bool,
    pub revoked_at: Option<DateTime<Utc>>,
    pub version: AuthorizationVersion,
    pub created_at: DateTime<Utc>,
    pub updated_at: Option<DateTime<Utc>>,
}

impl GroupMembership {
    pub fn new(
        oid: GroupMembershipOid,
        group_oid: GroupOid,
        user_oid: UserOid,
        granted_by_user_oid: Option<UserOid>,
        reason: impl Into<String>,
        created_at: DateTime<Utc>,
    ) -> Result<Self, GroupValidationError> {
        let reason = validate_reason(reason)?;
        Ok(Self {
            oid,
            group_oid,
            user_oid,
            granted_by_user_oid,
            reason,
            enabled: true,
            revoked_at: None,
            version: AuthorizationVersion::fresh(),
            created_at,
            updated_at: None,
        })
    }

    #[must_use]
    pub fn is_active(&self) -> bool {
        self.enabled && self.revoked_at.is_none()
    }

    /// Tombstone this relation. The OID is retained and can never be enabled
    /// again; a regrant creates a new relation.
    pub fn revoke(&mut self, now: DateTime<Utc>) -> Result<(), GroupLifecycleError> {
        if !self.is_active() {
            return Err(GroupLifecycleError::AlreadyRevoked);
        }
        self.enabled = false;
        self.revoked_at = Some(now);
        self.version = AuthorizationVersion::fresh();
        self.updated_at = Some(now);
        Ok(())
    }
}

/// Explicit group-to-role relation. Built-in groups define these as immutable
/// definitions; membership of the relation is managed separately.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GroupRole {
    pub oid: GroupRoleOid,
    pub group_oid: GroupOid,
    pub role_oid: RoleOid,
    pub granted_by_user_oid: Option<UserOid>,
    pub reason: String,
    pub enabled: bool,
    pub revoked_at: Option<DateTime<Utc>>,
    pub version: AuthorizationVersion,
    pub created_at: DateTime<Utc>,
    pub updated_at: Option<DateTime<Utc>>,
}

impl GroupRole {
    pub fn new(
        oid: GroupRoleOid,
        group_oid: GroupOid,
        role_oid: RoleOid,
        granted_by_user_oid: Option<UserOid>,
        reason: impl Into<String>,
        created_at: DateTime<Utc>,
    ) -> Result<Self, GroupValidationError> {
        let reason = validate_reason(reason)?;
        Ok(Self {
            oid,
            group_oid,
            role_oid,
            granted_by_user_oid,
            reason,
            enabled: true,
            revoked_at: None,
            version: AuthorizationVersion::fresh(),
            created_at,
            updated_at: None,
        })
    }

    #[must_use]
    pub fn is_active(&self) -> bool {
        self.enabled && self.revoked_at.is_none()
    }

    pub fn revoke(&mut self, now: DateTime<Utc>) -> Result<(), GroupLifecycleError> {
        if !self.is_active() {
            return Err(GroupLifecycleError::AlreadyRevoked);
        }
        self.enabled = false;
        self.revoked_at = Some(now);
        self.version = AuthorizationVersion::fresh();
        self.updated_at = Some(now);
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum GroupValidationError {
    #[error("group name is invalid or too long")]
    InvalidName,
    #[error("group description is invalid or too long")]
    InvalidDescription,
    #[error("group locale is invalid")]
    InvalidLocale,
    #[error("the independent default group name is required")]
    NameRequired,
    #[error("a locale may appear only once per text collection")]
    DuplicateLocale,
    #[error("group metadata contains too many entries")]
    TooManyEntries,
    #[error("optional group relationship note exceeds the length limit")]
    InvalidReason,
    #[error("built-in group definitions are immutable")]
    BuiltInDefinition,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum GroupLifecycleError {
    #[error("group relation is already revoked")]
    AlreadyRevoked,
}

/// Normalize an optional membership/role audit annotation. A blank value is
/// accepted and stored as an empty string; only over-long supplied text is
/// rejected.
pub fn validate_reason(value: impl Into<String>) -> Result<String, GroupValidationError> {
    let value = value.into();
    let trimmed = value.trim();
    if trimmed.chars().count() > MAX_GROUP_REASON_LENGTH {
        return Err(GroupValidationError::InvalidReason);
    }
    Ok(trimmed.to_owned())
}

/// Validate a complete localized metadata value for a group.
///
/// The same shared canonical language-tag rules used by roles and permissions
/// run in the application service and inside the write transaction. Translation
/// collections are optional and have no stored default language.
pub fn validate_group_metadata(metadata: &LocalizedMetadata) -> Result<(), GroupValidationError> {
    validate_group_names(&metadata.names)?;
    validate_group_descriptions(&metadata.descriptions)?;
    Ok(())
}

pub fn validate_group_names(entries: &[LocalizedText]) -> Result<(), GroupValidationError> {
    validate_text_entries(
        entries,
        MAX_GROUP_NAME_LENGTH,
        GroupValidationError::InvalidName,
        true,
    )
}

pub fn validate_group_descriptions(entries: &[LocalizedText]) -> Result<(), GroupValidationError> {
    validate_text_entries(
        entries,
        MAX_GROUP_DESCRIPTION_LENGTH,
        GroupValidationError::InvalidDescription,
        false,
    )
}

fn validate_text_entries(
    entries: &[LocalizedText],
    max_value_length: usize,
    invalid_value: GroupValidationError,
    name_required: bool,
) -> Result<(), GroupValidationError> {
    if entries.len() > MAX_GROUP_TEXT_ENTRIES {
        return Err(GroupValidationError::TooManyEntries);
    }
    let mut seen = BTreeSet::new();
    for entry in entries {
        let canonical =
            canonicalize_locale(&entry.locale).map_err(|_| GroupValidationError::InvalidLocale)?;
        if !seen.insert(canonical) {
            return Err(GroupValidationError::DuplicateLocale);
        }
        let value = entry.value.trim();
        if name_required && value.is_empty() {
            return Err(invalid_value);
        }
        if value.chars().count() > max_value_length {
            return Err(invalid_value);
        }
    }
    Ok(())
}

pub fn validate_locale(value: &str) -> Result<(), GroupValidationError> {
    canonicalize_locale(value)
        .map(|_| ())
        .map_err(|_| GroupValidationError::InvalidLocale)
}

/// Validate independent fallback text; translated collections may be empty.
pub fn validate_group_default(value: &str, name: bool) -> Result<String, GroupValidationError> {
    let value = value.trim();
    if name && value.is_empty() {
        return Err(GroupValidationError::NameRequired);
    }
    let (max, error) = if name {
        (MAX_GROUP_NAME_LENGTH, GroupValidationError::InvalidName)
    } else {
        (
            MAX_GROUP_DESCRIPTION_LENGTH,
            GroupValidationError::InvalidDescription,
        )
    };
    if value.chars().count() > max {
        return Err(error);
    }
    Ok(value.to_owned())
}

#[cfg(test)]
mod tests {
    use chrono::Utc;

    use super::{
        Group, GroupMembership, GroupRole, GroupValidationError, LocalizedMetadata, LocalizedText,
        validate_group_metadata,
    };
    use crate::{
        rbac::ids::{GroupMembershipOid, GroupOid, GroupRoleOid, RoleOid},
        user::UserOid,
    };
    use uuid::Uuid;

    fn metadata(names: &[(&str, &str)], descriptions: &[(&str, &str)]) -> LocalizedMetadata {
        LocalizedMetadata::canonicalize(
            names
                .iter()
                .map(|(locale, value)| LocalizedText::new(*locale, *value))
                .collect(),
            descriptions
                .iter()
                .map(|(locale, value)| LocalizedText::new(*locale, *value))
                .collect(),
        )
        .expect("test metadata should be canonical")
    }

    #[test]
    fn built_in_group_definitions_are_immutable() {
        let metadata = metadata(&[("en-US", "Owner")], &[]);
        let mut group = Group::built_in(
            GroupOid::new(),
            "Owners".into(),
            "".into(),
            metadata.clone(),
            Utc::now(),
        )
        .expect("built-in group");
        assert!(group.ensure_definition_mutable().is_err());
        assert!(matches!(
            group.update_metadata(Some(metadata), Utc::now()),
            Err(GroupValidationError::BuiltInDefinition)
        ));
        assert!(matches!(
            group.set_enabled(false, Utc::now()),
            Err(GroupValidationError::BuiltInDefinition)
        ));
        assert!(group.enabled);
        assert!(group.built_in);
    }

    #[test]
    fn enabling_an_enabled_group_is_a_noop() {
        let mut group = Group::new(
            GroupOid::new(),
            "Auditors".into(),
            "".into(),
            metadata(&[("en-US", "Auditors")], &[]),
            Utc::now(),
        )
        .expect("custom group");
        let version = group.version;
        assert_eq!(group.set_enabled(true, Utc::now()), Ok(false));
        assert_eq!(group.version, version);
    }

    #[test]
    fn blank_membership_and_role_annotation_hydrate_as_empty() {
        let membership = GroupMembership::new(
            GroupMembershipOid::new(),
            GroupOid::new(),
            UserOid(Uuid::new_v4()),
            None,
            "   ",
            Utc::now(),
        )
        .expect("blank membership reason is optional");
        assert_eq!(membership.reason, "");

        let binding = GroupRole::new(
            GroupRoleOid::new(),
            GroupOid::new(),
            RoleOid::new(),
            None,
            "",
            Utc::now(),
        )
        .expect("blank role binding reason is optional");
        assert_eq!(binding.reason, "");
    }

    #[test]
    fn metadata_edits_rotate_the_row_version() {
        let mut group = Group::new(
            GroupOid::new(),
            "Auditors".into(),
            "".into(),
            metadata(&[("en-US", "Auditors")], &[]),
            Utc::now(),
        )
        .expect("custom group");
        let version = group.version;
        group
            .update_metadata(
                Some(metadata(&[("en-US", "Security auditors")], &[])),
                Utc::now(),
            )
            .expect("metadata update");
        assert_ne!(group.version, version);
        assert_eq!(group.metadata.base_name(), Some("Security auditors"));
        assert_eq!(
            group.name, "Auditors",
            "translation edits preserve default text"
        );
    }

    #[test]
    fn group_metadata_rejects_duplicate_aliases_and_allows_no_translations() {
        let duplicate = LocalizedMetadata {
            names: vec![
                LocalizedText::new("en-US", "Owner"),
                LocalizedText::new("en_us", "Owner again"),
            ],
            descriptions: Vec::new(),
        };
        assert!(matches!(
            validate_group_metadata(&duplicate),
            Err(GroupValidationError::DuplicateLocale)
        ));

        assert!(validate_group_metadata(&LocalizedMetadata::default()).is_ok());
    }
}
