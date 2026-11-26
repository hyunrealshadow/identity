//! User-group management error catalog. Reserved range: 19000-19099.
//!
//! Cursor and page-argument failures keep using the shared business RBAC codes
//! (17037/17038/17039); every group-specific failure is defined here.

define_error_codes! {
    pub enum GroupErrorCode(module = "rbac.group") {
        ValidationFailed = 19000 { kind: Validation, optional: [field] },
        GroupNotFound = 19001 { kind: NotFound },
        MembershipNotFound = 19002 { kind: NotFound, module: "rbac.group.membership" },
        RoleBindingNotFound = 19003 { kind: NotFound, module: "rbac.group.roles" },
        VersionConflict = 19004 { kind: Conflict, required: [current_version] },
        InvalidName = 19006 { kind: Validation, optional: [max] },
        InvalidDescription = 19007 { kind: Validation, optional: [max] },
        InvalidLocale = 19008 { kind: Validation, optional: [max] },
        BuiltInProtected = 19010 { kind: Forbidden, optional: [key] },
        Disabled = 19011 { kind: Conflict, module: "rbac.group.membership" },
        InvalidReason = 19012 { kind: Validation, required: [max] },
        InvalidVersion = 19013 { kind: Validation },
        InvalidClientMutationId = 19014 { kind: Validation, required: [max] },
        EmptyUpdate = 19015 { kind: Validation },
        InvalidCollectionSize = 19016 { kind: Validation, required: [max] },
        RoleNotFound = 19017 { kind: NotFound, module: "rbac.group.roles" },
        RoleDisabled = 19018 { kind: Conflict, module: "rbac.group.roles" },
        DelegationCeilingExceeded = 19019 { kind: Forbidden, required: [scope], module: "rbac.group.delegation" },
        MembershipAlreadyActive = 19020 { kind: Conflict, module: "rbac.group.membership" },
        MembershipNotActive = 19021 { kind: Conflict, module: "rbac.group.membership" },
        StorageFailed = 19022 { kind: Internal },
        InvalidFilter = 19025 { kind: Validation, required: [field], optional: [max] },
        UserNotFound = 19026 { kind: NotFound, module: "rbac.group.membership" },
        InvalidMetadata = 19027 { kind: Validation, required: [field] },
        DuplicateLocale = 19028 { kind: Validation, optional: [locale] },
        NameRequired = 19029 { kind: Validation },
    }
}
