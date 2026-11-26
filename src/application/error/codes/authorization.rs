//! Authorization error catalog. Reserved range: 27000-27099.

define_error_codes! {
    pub enum AuthorizationErrorCode(module = "authorization") {
        InvalidPrincipal = 27000 { kind: Unauthorized, optional: [principal_kind], module: "authorization.policy" },
        MissingPrincipal = 27001 { kind: Unauthorized, optional: [principal_kind], module: "authorization.guards" },
        InsufficientScope = 27002 { kind: Forbidden, required: [required_scope], module: "authorization.guards" },
        ForbiddenManagementAuthority = 27003 { kind: Forbidden, optional: [required_scope], module: "authorization.policy" },
        TargetForbidden = 27004 { kind: Forbidden, optional: [target_type], module: "authorization.policy" },
        AuthorizationVersionStale = 27005 { kind: Unauthorized, module: "authorization.snapshot" },
        AuthorizationSnapshotExpired = 27006 { kind: Unauthorized, module: "authorization.snapshot" },
        LastOwnerProtected = 27007 { kind: Conflict, module: "authorization.owner" },
        OwnerTargetProtected = 27008 { kind: Forbidden, module: "authorization.owner" },
        GrantNotFound = 27011 { kind: NotFound, module: "authorization.snapshot" },
        DuplicatePermissionCode = 27014 { kind: Conflict, optional: [permission], module: "rbac.repository" },
        ReservedManagementScope = 27015 { kind: Validation, required: [scope], module: "authorization.catalog" },
        InvalidManagementScope = 27016 { kind: Validation, required: [scope], module: "authorization.catalog" },
        BusinessScopeBoundaryViolation = 27017 { kind: Validation, required: [scope], optional: [reason_code], module: "rbac.boundary" },
        RbacPolicyUnavailable = 27018 { kind: Internal, module: "rbac.policy" },
        AuditWriteFailed = 27019 { kind: Internal, module: "authorization.audit" },
        InvalidTarget = 27020 { kind: Validation, optional: [target_type], module: "authorization.policy" },
        MissingHumanAuthentication = 27021 { kind: Unauthorized, required: [required_authentication], module: "authorization.policy" },
        HumanOnlyManagementCapability = 27022 { kind: Forbidden, required: [scope], module: "authorization.policy" },
        MachineAssuranceNotAllowed = 27023 { kind: Forbidden, module: "authorization.policy" },
        AuthorizationSnapshotOidMismatch = 27024 { kind: Unauthorized, module: "authorization.snapshot" },
        InvalidPermissionDefinition = 27026 { kind: Validation, optional: [field], module: "rbac.model" },
        InvalidRoleDefinition = 27027 { kind: Validation, optional: [field], module: "rbac.model" },
        VersionConflict = 27028 { kind: Conflict, required: [current_version], module: "administrator.repository" },
    }
}
