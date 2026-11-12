const enUS = {
  rbacPageCount: '{count} items on this page',
  rbacLabelsUnavailable: 'Some permission details could not be loaded',

  rbacApiResource: 'API resource',
  rbacSearchApi: 'Search APIs',
  rbacNoResources: 'No APIs found',
  rbacLoadMore: 'Load more',
  rbacPermissionDescription: 'Description',
  rbacRoleSource: 'Role',
  rbacGroupSource: 'Group',
  rbacUserPermissionsIntro: 'Permissions inherited from roles and groups',
  rbacEntityEdit: 'Edit details',
  rbacEntityCreated: 'Created',
  rbacEntityUpdated: 'Updated',
  rbacEntityName: 'Name',
  rbacEntityDescription: 'Description',
  rbacAllApis: 'All APIs',
  rbacEntityStatus: 'Status',

  usersTitle: 'Users',
  usersDescription: 'Browse, create, and manage users in this instance.',
  usersNewTitle: 'New user',
  usersNewDescription:
    'Create a user, set an initial password, and add optional profile details.',
  usersNewAction: 'New user',
  backToUsers: 'Back to users',
  previousPage: 'Previous page',
  nextPage: 'Next page',
  usersTableLabel: 'Users',
  usersTableLoading: 'Loading users…',
  usersColumnUser: 'User',
  usersColumnStatus: 'Status',
  usersColumnCreated: 'Created',
  usersColumnUpdated: 'Updated',
  usersEnabled: 'Enabled',
  usersDisabled: 'Disabled',
  usersLocked: 'Locked',
  usersPaginationLabel: 'User list pagination',
  usersPageSummary:
    '{count, plural, one {# user on this page} other {# users on this page}}',
  usersPartialTitle: 'Some user data could not be loaded',
  usersPartialDescription:
    'The list is usable, but the server returned one or more errors.',
  usersEmptyTitle: 'No users yet',
  usersEmptyDescription:
    'This instance does not have any user records to display.',
  usersNoResultsTitle: 'No users match these filters',
  usersNoResultsDescription: 'Adjust or reset the filters to see other users.',
  usersClearFilters: 'Clear filters',
  usersNoReadTitle: 'User records cannot be read',
  usersNoReadWriteOnlyDescription:
    'This account has user write grants but does not have users.read. No user records were requested, displayed, or inferred. You can still create a user when users.create is granted.',
  usersNoManagementTitle: 'You do not have user management access',
  usersNoManagementDescription:
    'This account can sign in, but it does not have any effective user management permission.',
  usersStepUpDescription:
    'Complete two-step verification to use user management.',
  usersStepUpNote:
    'After authenticating, return to this page and continue. No action was replayed automatically.',
  usersCreateNoPermissionTitle: 'You cannot create users',
  usersCreateNoPermissionDescription:
    'This account does not have the users.create permission.',
  usersCreateOnlyAccessTitle: 'Write-only user access',
  usersCreateReadWarning:
    'This account can create users but cannot read user records. After creation, only the new user ID and version will be shown.',
  usersCreateCannotReadTitle: 'The user was created but cannot be viewed',
  usersCreateCannotReadDescription:
    'The user was created with ID {userId}. This account cannot read user records, so no profile data is shown.',
  usersCreateAnother: 'Create another user',
  usersUserIdLabel: 'User ID',
  usersVersionLabel: 'Version',
  usersFiltersTitle: 'Filters',
  usersFiltersDescription:
    'Search, filter, and order users. Changing a filter or the order starts a new page.',
  usersAdvancedFiltersShow: 'Show advanced filters',
  usersAdvancedFiltersHide: 'Hide advanced filters',
  usersAdvancedFiltersActive:
    '{count, plural, one {# filter selected} other {# filters selected}}',
  usersFilterSearchLabel: 'Search',
  usersFilterSearchPlaceholder: 'Username or email',
  usersFilterSearchDescription: 'Searches usernames and email addresses.',
  usersFilterUsernameLabel: 'Username',
  usersFilterEmailLabel: 'Email',
  usersFilterEnabledLabel: 'Account status',
  usersFilterLockedLabel: 'Lock status',
  usersFilterCreatedFromLabel: 'Created from',
  usersFilterCreatedBeforeLabel: 'Created before',
  usersFilterOrderLabel: 'Order',
  usersFilterAny: 'Any',
  usersFilterEnabledOnly: 'Enabled only',
  usersFilterDisabledOnly: 'Disabled only',
  usersFilterLockedOnly: 'Locked only',
  usersFilterUnlockedOnly: 'Unlocked only',
  usersFilterDateHint:
    'Dates use your time zone. The start date is inclusive; the end date is exclusive.',
  usersFilterQueryTooLong: 'Search must be 255 characters or fewer.',
  usersFilterUsernameTooLong:
    'The username filter must be 64 characters or fewer.',
  usersFilterEmailTooLong: 'The email filter must be 320 characters or fewer.',
  usersFilterDateInvalid: 'Enter a valid date.',
  usersFilterDateRange: 'The start date must be before the end date.',
  usersFilterInvalidTitle: 'Fix the filters before loading users',
  usersFilterInvalidDescription:
    'The filter values are invalid, so no user query was sent.',
  usersApplyFilters: 'Apply filters',
  usersResetFilters: 'Reset filters',
  usersOrderCreatedDesc: 'Newest first',
  usersOrderCreatedAsc: 'Oldest first',
  usersOrderUsernameAsc: 'Username A-Z',
  usersOrderUsernameDesc: 'Username Z-A',
  usersSectionAccount: 'Account identifiers',
  usersCreateAccountDescription:
    'Enter a username, email address, and initial password.',
  usersFieldUsername: 'Username',
  usersFieldEmail: 'Email',
  usersFieldPassword: 'Initial password',
  usersFieldPasswordDescription:
    'The initial password will not be shown again after the user is created.',
  usersCreateDraftPasswordHint:
    'Your saved draft was restored. Re-enter the initial password to continue.',
  usersEmailVerificationNote:
    'Email verification cannot be changed in this console. New users and changed email addresses are treated as unverified.',
  usersSectionProfile: 'Optional profile',
  usersAdditionalProfile: 'Additional profile fields',
  usersSectionProfileDescription:
    'Optional profile values. Empty fields are omitted.',
  usersFieldGivenName: 'Given name',
  usersFieldFamilyName: 'Family name',
  usersFieldMiddleName: 'Middle name',
  usersFieldNickname: 'Nickname',
  usersFieldProfile: 'Profile URL',
  usersFieldPicture: 'Picture URL',
  usersFieldWebsite: 'Website',
  usersFieldBirthdate: 'Birthdate',
  usersFieldLocale: 'Locale',
  usersFieldTheme: 'Theme',
  usersUsernameRequired: 'Enter a username.',
  usersEmailRequired: 'Enter an email address.',
  usersCreatePasswordRequired: 'Enter an initial password.',
  usersCreateAction: 'Create user',
  usersCreatePending: 'Creating user…',
  usersCreateSuccessToast: 'User created',
  usersCreateCommitted: 'User created.',
  usersPartialMutationNote:
    'The write returned a committed result with one or more warnings. Review the details before continuing.',
  usersMutationFailedTitle: 'The action was not confirmed',
  usersMutationFailedDescription:
    'Review the error details before trying again. The action was not replayed automatically.',
  usersConflictTitle: 'The user changed while you were working',
  usersConflictDescription:
    'Reload the user before making changes. The action was not replayed.',
  usersConflictCurrentVersion: 'Reload the user before making changes.',
  usersConflictUnknownVersion: 'Reload the user before making changes.',
  usersReloadUser: 'Reload user',
  usersReloading: 'Reloading user…',
  usersColumnActions: 'Actions',
  usersViewDetails: 'View details',
  usersViewDetailsFor: 'View details for {username}',
  usersEditFor: 'Edit {username}',

  usersDetailTitle: 'User details',
  usersDetailLoading: 'Loading user details…',
  usersDetailDescription: 'Review this user’s account, profile, and status.',
  usersDetailAvatarLabel: 'Avatar for {username}',
  usersMoreActions: 'More actions',
  usersDetailMoreProfile: 'More profile details',
  usersAccountTitle: 'Account',
  usersProfileEmpty: 'No profile information',
  usersAccountDescription: 'Identifiers and timestamps for this user.',
  usersEmailVerified: 'Verified',
  usersEmailUnverified: 'Not verified',
  usersCreatedAtLabel: 'Created',
  usersUpdatedAtLabel: 'Updated',
  usersProfileTitle: 'Profile',
  usersDetailProfileDescription: 'Personal details for this user.',
  usersManagementTitle: 'Security status',
  usersManagementDescription:
    'Account lock, failed sign-in attempts, and current version.',
  usersLockedUntilLabel: 'Locked until',
  usersFailedAttemptsLabel: 'Failed attempts',
  usersStateTitle: 'Account state',
  usersStateDescription: 'Enable, disable, or unlock this account.',
  usersNoUpdatePermission:
    'This account can view this user but cannot edit the profile.',
  usersNoStatePermission:
    'This account can view this user but cannot change account state.',
  usersStateNoAction: 'No state change is currently available.',
  usersStateVersionUnavailable: 'Reload the user before making changes.',
  usersStateTarget: 'Target user',
  usersEnableAction: 'Enable user',
  usersDisableAction: 'Disable user',
  usersUnlockAction: 'Unlock user',
  usersEnableTitle: 'Enable this user?',
  usersDisableTitle: 'Disable this user?',
  usersUnlockTitle: 'Unlock this user?',
  usersEnableDescription:
    'The user may sign in and obtain new access after this change. Previous sessions and tokens are not restored.',
  usersDisableDescription:
    'All sessions, tokens, authorization codes, pending logins, challenges, and device authorizations for this user are revoked. The user cannot sign in until enabled again.',
  usersUnlockDescription:
    'This clears the lock, lock expiry, and failed authentication count. It does not enable a disabled account or restore previous access.',
  usersStateConfirmEnable: 'Enable user',
  usersStateConfirmDisable: 'Disable user',
  usersStateConfirmUnlock: 'Unlock user',
  usersStatePending: 'Applying change…',
  usersStateEnabledToast: 'User enabled',
  usersStateDisabledToast: 'User disabled',
  usersStateUnlockedToast: 'User unlocked',
  usersStateCommitted: 'User status updated.',
  usersStateSavedTitle: 'User state saved',
  usersStateAccessLostTitle: 'The change was saved',
  usersStateAccessLostDescription:
    'User data can no longer be read with this console session. The write itself completed successfully.',
  usersStateRefreshFailedTitle:
    'The change was saved but the user could not be reloaded',
  usersStateRefreshFailedDescription:
    'Retry loading the user. Do not submit the state change again.',
  usersSelfDisabledTitle: 'Your account was disabled',
  usersSelfDisabledDescription:
    'The disablement was committed. This console session may no longer be able to read user data.',

  usersEditTitle: 'Edit user',
  usersEditDescription:
    'Change this user’s account identifiers and basic profile details.',
  usersEditAccountDescription:
    'Update the username and email address used to identify this user.',
  usersEditProfileDescription:
    'Set the optional given name, family name, or nickname.',
  usersEditSparseHint:
    'Only changed fields are included in the update request.',
  usersEditNoChanges: 'Make at least one change before saving.',
  usersEditEmailVerifiedReset:
    'Changing the email address marks it as unverified.',
  usersEditAction: 'Edit user',
  usersEditSaveAction: 'Save changes',
  usersEditPending: 'Saving changes…',
  usersEditSuccessToast: 'User updated',
  usersEditCommitted: 'Changes saved.',
  usersEditNoPermissionTitle: 'You cannot edit this user',
  usersEditNoPermissionDescription:
    'This account does not have the users.update permission.',
  usersBackToDetail: 'Back to user details',

  rbacStepUpTitle: 'Stronger authentication is required',
  rbacStepUpDescription:
    'Complete two-step verification to continue with this action.',
  rbacStepUpNote:
    'After authenticating, review this page and submit again. Nothing was replayed automatically.',
  rbacConflictTitle: 'The role data changed while you were working',
  rbacConflictDescription:
    'Reload the latest version before trying again. The action was not replayed.',
  rbacConflictCurrentVersion: 'Current version: {version}',
  rbacConflictUnknownVersion: 'The server did not include the current version.',
  rbacReload: 'Reload data',
  rbacReloading: 'Reloading data…',
  rbacMutationFieldDescription:
    'Review the highlighted fields before trying again. The action was not replayed.',
  rbacPartialMutationNote:
    'The write returned a committed result with one or more warnings. Review the details before continuing.',
  userDetailTabsLabel: 'User detail sections',
  userDetailsTabProfile: 'Profile',
  userDetailsTabGroups: 'Groups',
  userDetailsTabRoles: 'Roles',
  userDetailsTabPermissions: 'Permissions',
  roleDetailTabsLabel: 'Role detail sections',
  roleTabSettings: 'Details',
  roleTabPermissions: 'Permissions',
  roleTabUsers: 'Users',
  backToRoles: 'Back to roles',

  rolesTitle: 'Roles',
  rolesDescription:
    'Create roles and configure their permission membership and users.',
  rolesNewTitle: 'New role',
  rolesNewDescription:
    'Create a stable role. Roles are not assigned to users automatically.',
  rolesNewAction: 'New role',
  rolesTableLabel: 'Roles',
  rolesTableLoading: 'Loading roles…',
  rolesColumnRole: 'Role',
  rolesColumnStatus: 'Status',
  rolesColumnCreated: 'Created',
  rolesColumnUpdated: 'Updated',
  rolesColumnActions: 'Actions',
  rolesViewAction: 'View details',
  rolesViewFor: 'View details for {name}',
  rolesEnabled: 'Enabled',
  rolesDisabled: 'Disabled',
  rolesPaginationLabel: 'Role list pagination',
  rolesPageSummary:
    '{count, plural, one {# item on this page} other {# items on this page}}',
  rolesPartialTitle: 'Some role data could not be loaded',
  rolesPartialDescription:
    'The page remains usable, but the server returned one or more errors.',
  rolesEmptyTitle: 'No roles yet',
  rolesEmptyDescription: 'This instance does not have any roles to display.',
  rolesNoResultsTitle: 'No roles match these filters',
  rolesNoResultsDescription: 'Adjust or reset the filters to see other roles.',
  rolesClearFilters: 'Clear filters',
  rolesFiltersTitle: 'Role filters',
  rolesFilterSearchLabel: 'Search',
  rolesFilterSearchPlaceholder: 'Name',
  rolesFilterStatusLabel: 'Status',
  rolesFilterAny: 'Any',
  rolesFilterEnabled: 'Enabled only',
  rolesFilterDisabled: 'Disabled only',
  rolesFilterOrderLabel: 'Order',
  rolesOrderNameAsc: 'Name A-Z',
  rolesOrderNameDesc: 'Name Z-A',
  rolesOrderCreatedDesc: 'Newest first',
  rolesOrderCreatedAsc: 'Oldest first',
  rolesApplyFilters: 'Apply filters',
  rolesResetFilters: 'Reset filters',
  rolesNoReadTitle: 'Role records cannot be read',
  rolesNoReadDescription:
    'This account does not have management.role.read, so no role records were requested or inferred.',
  rolesCreateNoPermissionTitle: 'You cannot create roles',
  rolesCreateNoPermissionDescription:
    'This account does not have management.role.write.',
  rolesCreateWriteOnlyTitle: 'The role was created but cannot be viewed',
  rolesCreateWriteOnlyDescription:
    'The role was created with ID {roleId}. This account cannot read role records, so no role details are shown.',
  rolesCreateAnother: 'Create another role',
  rolesCreateSuccessToast: 'Role created',
  rolesCreateCommitted: 'Role created.',
  rolesCreatePending: 'Creating role…',
  rolesCreateAction: 'Create role',
  rolesFieldName: 'Name',
  rolesFieldDescription: 'Description',
  rolesNameRequired: 'Enter a role name.',
  rolesNoReadAfterCreateTitle: 'Write-only role access',
  rolesNoReadAfterCreateDescription:
    'This account can create a role but cannot read role records. Only the new role ID and version will be shown after creation.',
  rolesFormStepUpNote:
    'Your form values are preserved. After authenticating, return here and submit again; the mutation is not replayed automatically.',
  rolesIdLabel: 'Role ID',
  rolesVersionLabel: 'Version',
  rolesCreatedAtLabel: 'Created',
  rolesUpdatedAtLabel: 'Updated',
  rolesBuiltInBadge: 'Built-in',
  rolesBuiltInReadonlyTitle: 'Built-in role definition',
  rolesBuiltInReadonlyDescription:
    'This role’s definition, enabled state, and permission relationships are fixed by the system. You can review them here, but they cannot be edited.',
  rolesBuiltInStateReadonly:
    'The enabled state of a built-in role is fixed by the system.',
  rolesBuiltInPermissionsReadonly:
    'Built-in role permissions are fixed by the system. The assigned permissions are shown for review and cannot be edited.',
  rolesMetadataSectionTitle: 'Localized display text',
  rolesMetadataSectionDescription:
    'Provide a default name. Translations and descriptions are optional.',
  rolesMetadataNameRequired: 'Enter a default name.',

  roleDetailTitle: 'Role settings',
  roleDetailDescription:
    'Update role details, permissions, and user assignments.',
  roleSettingsTitle: 'Details',
  permissionSettingsTitle: 'Basic information',
  roleSettingsDescription: 'Update the role name and description.',
  roleSettingsSparseHint: 'Unchanged details will be kept.',
  roleSettingsSaveAction: 'Save changes',
  roleSettingsSavedToast: 'Role updated',
  roleSettingsSavedTitle: 'Role settings saved',
  roleSettingsCommitted: 'Role changes saved.',
  roleRefreshFailedTitle:
    'The change was saved but the role could not be reloaded',
  roleRefreshFailedDescription:
    'Reload the role before making another change. Do not repeat the same write.',
  rolesEditDiscard: 'Discard changes',
  rolesVersionUnavailable:
    'The current version is unavailable. Reload the role before changing it.',
  roleStatusTitle: 'Role status',
  rolesEnableAction: 'Enable role',
  rolesDisableAction: 'Disable role',
  rolesEnableTitle: 'Enable this role?',
  rolesDisableTitle: 'Disable this role?',
  rolesEnableDescription:
    'The role will be available for new authorizations. Revoked user assignments will remain revoked.',
  rolesDisableDescription:
    'This role will stop granting permissions. User assignment records will be kept.',
  rolesEnableConfirm: 'Enable role',
  rolesDisableConfirm: 'Disable role',
  rolesEnabledToast: 'Role enabled',
  rolesDisabledToast: 'Role disabled',
  rolesStateStepUpHint:
    'Stronger authentication is required before changing role state.',
  rolesNoStatePermission:
    'This account can view this role but cannot change its state.',

  rolePermissionsTitle: 'Role permissions',
  rolePermissionsDescription:
    'Choose the API permissions available to this role.',
  rolePermissionsNoCatalogTitle: 'Permission catalog cannot be read',
  rolePermissionsNoCatalogDescription:
    'Your account does not have access to the permission catalog.',
  rolePermissionsCurrentTitle: 'Assigned permissions',
  rolePermissionsCurrentDescription:
    'Review all assigned permissions. Disabled permissions can still be removed.',
  roleMembershipLoading: 'Loading role permissions…',
  roleMembershipLoadFailedTitle: 'Role permissions could not be loaded',
  roleMembershipLoadFailedDescription:
    'Reload all assigned permissions before saving changes.',
  rolePermissionsNoneTitle: 'This role has no permissions',
  rolePermissionsNoneDescription:
    'Use Add permissions to assign permissions to this role.',
  rolePermissionsCatalogTitle: 'Permission catalog',
  rolePermissionsCatalogDescription:
    'Search the catalog and select explicit permissions. Results are grouped by API resource.',
  rolePermissionsCatalogSearchLabel: 'Search permissions',
  rolePermissionsCatalogSearchPlaceholder: 'Permission code',
  rolePermissionsCatalogStatusLabel: 'Permission status',
  rolePermissionsCatalogApply: 'Search catalog',
  rolePermissionsCatalogLoading: 'Loading permission catalog…',
  rolePermissionsCatalogEmptyTitle: 'No permissions match the catalog search',
  rolePermissionsCatalogEmptyDescription:
    'Adjust the search or resource filter to see other permissions.',
  rolePermissionsCatalogPagination: 'Permission catalog pagination',
  rolePermissionsCatalogLoadFailed:
    'The permission catalog could not be loaded.',
  rolePermissionsToggleLabel: 'Toggle permission {code}',
  rolePermissionsPermissionDisabled: 'Disabled',
  rolePermissionsReplaceTitle: 'Save permission changes',
  rolePermissionsReplaceDescription:
    'Saving applies the permissions currently selected for this role.',
  rolePermissionsIncompleteWarning:
    'Saving is disabled until every existing membership page loads successfully.',
  rolePermissionsDisabledSelectedHint:
    '{count, plural, one {# selected permission is disabled} other {# selected permissions are disabled}} and can still be removed.',
  rolePermissionsAddedCount:
    '{count, plural, one {# addition} other {# additions}}',
  rolePermissionsRemovedCount:
    '{count, plural, one {# removal} other {# removals}}',
  rolePermissionsSelectedCount:
    '{count, plural, one {# selected} other {# selected}}',
  rolePermissionsAtomicHint:
    'Deselecting a permission removes it from this role.',
  rolePermissionsSaveAction: 'Review and save',
  rolePermissionsResetSelection: 'Reset selection',
  rolePermissionsConfirmTitle: 'Replace role permissions?',
  rolePermissionsConfirmDescription:
    'Review the permissions being added and removed.',
  rolePermissionsConfirmAction: 'Replace permissions',
  rolePermissionsAddedLabel: 'Adding',
  rolePermissionsRemovedLabel: 'Removing',
  rolePermissionsCount:
    '{count, plural, one {# permission} other {# permissions}}',
  rolePermissionsSavedToast: 'Role permissions updated',
  rolePermissionsSavedTitle: 'Role permissions updated',
  rolePermissionsSavedDescription:
    'The role’s permission membership was saved. Review the refreshed list before making another change.',
  rolePermissionsReloadHint:
    'Membership was reloaded from the server. Review the latest state before another change.',
  rolePermissionReady: 'All assigned permissions are loaded and ready to edit.',
  rolePermissionsNoChanges: 'Change the selected permissions before saving.',
  rolePermissionsTableLabel: 'Assigned and pending role permissions',
  rolePermissionsToolbarLabel: 'Permission actions',
  rolePermissionsColumnPermission: 'Permission',
  rolePermissionsColumnDescription: 'Description',
  rolePermissionsColumnResource: 'API resource',
  rolePermissionsColumnStatus: 'Status',
  rolePermissionsColumnActions: 'Actions',
  rolePermissionsAddAction: 'Add permissions',
  rolePermissionsAddTitle: 'Add permissions',
  rolePermissionsPickerDescription:
    'Search the permission catalog for {role}. Existing assignments are shown as already assigned.',
  rolePermissionsPickerSelectedCount:
    '{count, plural, one {# selected to add} other {# selected to add}}',
  rolePermissionsPickerAlreadyAssigned: 'Already assigned',
  rolePermissionsPickerAllResources: 'All resources',
  rolePermissionsPickerResourceLabel: 'API resource',
  rolePermissionsPickerResourceSearchLabel: 'Find resource',
  rolePermissionsPickerResourceSearchPlaceholder: 'Resource name or URI',
  rolePermissionsPickerResourcePrevious: 'Previous resources',
  rolePermissionsPickerResourceNext: 'Next resources',
  rolePermissionsPickerResourceGroupLabel: 'Resource options pagination',
  rolePermissionsPickerResourceLoading: 'Loading resources…',
  rolePermissionsPickerResourceEmpty: 'No resources match this search.',
  rolePermissionsPickerResourceError: 'API resources could not be loaded.',
  rolePermissionsPickerResultsLabel: 'Permission catalog results',
  rolePermissionsPickerAddSelected: 'Add selected',
  rolePermissionsStatusAssigned: 'Assigned',
  rolePermissionsStatusAssignedDisabled: 'Assigned · disabled',
  rolePermissionsStatusAdded: 'Pending addition',
  rolePermissionsStatusRemoved: 'Pending removal',
  rolePermissionsRemoveAction: 'Remove',
  rolePermissionsRemoveFor: 'Remove {code} from this role',
  rolePermissionsUndoRemoval: 'Undo removal',
  rolePermissionsUndoFor: 'Undo removal of {code}',
  rolePermissionsResourceUnavailable: 'Not available',
  permissionBuiltInBadge: 'Built-in',
  rolePermissionsProtectedHint:
    'Built-in permissions can be assigned to custom roles. Their definitions are read-only.',
  rolesPermissionsStepUpNote:
    'Your selection is local until you authenticate again. Nothing is submitted automatically.',

  roleUsersTitle: 'Role users',
  roleUsersDescription:
    'Manage users assigned to this role and review assignment history.',
  roleUsersNoReadTitle: 'Role assignments cannot be read',
  roleUsersNoReadDescription:
    'This account does not have management.role_assignment.read, so user-role assignments were not requested.',
  rolesUsersStepUpNote:
    'Stronger authentication is required before assigning or revoking a user role.',
  roleUsersListTitle: 'User assignments',
  roleUsersListDescription:
    'Review current assignments and previously revoked assignments.',
  roleUsersLoading: 'Loading role users…',
  roleUsersEmptyTitle: 'No user assignments',
  roleUsersEmptyDescription:
    'No user has been assigned this role, including revoked history.',
  roleUsersEmptyFilteredDescription:
    'No user assignments match the selected status.',
  roleUsersTableLabel: 'Role users',
  roleUsersColumnUser: 'User',
  roleUsersColumnStatus: 'Assignment status',
  roleUsersColumnCreated: 'Granted',
  roleUsersColumnActions: 'Actions',
  roleUsersPagination: 'Role user pagination',
  roleUsersNoWritePermission: 'No assignment write permission',
  roleUsersAssignAction: 'Assign user',
  roleUsersAssignTitle: 'Assign this role to a user',
  roleUsersAssignDescription: 'Choose a user to assign the role “{role}”.',
  roleUsersSearchUsers: 'Search users',
  roleUsersSearchAction: 'Search',
  roleUsersNoCandidates: 'No users match this search.',
  roleUsersSelectUserRequired: 'Choose a user before assigning this role.',
  roleUsersAssignConfirm: 'Assign role',
  roleUserAssignedTitle: 'User role assigned',
  roleUserAssignedDescription:
    'The user-role assignment was refreshed from the server.',
  roleUserAssignedToast: 'User role assigned',
  roleUserAssignedCommitted:
    '{count, plural, one {# new assignment created} other {# new assignments created}}.',
  roleUserAlreadyAssigned:
    'The user already had an active assignment, so none was added.',
  roleUsersRevokeAction: 'Revoke',
  roleUsersRevokeFor: 'Revoke this role from {user}',
  roleUsersRevokeTitle: 'Revoke this user-role assignment?',
  roleUsersRevokeDescription:
    'Revoke this role from {user}. The assignment remains as revocation history, and assigning the role again creates a new one.',
  roleUsersRevokeConfirm: 'Revoke role',
  roleUserRevokedTitle: 'User role revoked',
  roleUserRevokedDescription:
    'The assignment was refreshed from the server and remains visible in history.',
  roleUserRevokedToast: 'User role revoked',
  roleUserRevokedCommitted:
    '{count, plural, one {# assignment revoked} other {# assignments revoked}}.',
  assignmentFilterAll: 'All statuses',
  authorizationSourceFilterLabel: 'Source',
  authorizationSourceAny: 'All sources',
  authorizationSourceDirect: 'Direct',
  authorizationSourceGroup: 'Inherited from group',
  assignmentFilterActive: 'Active',
  assignmentFilterRevoked: 'Revoked',
  assignmentActive: 'Active',
  assignmentRevoked: 'Revoked',
  assignmentActiveRoleDisabled: 'Active · role disabled',
  assignmentRoleDisabledHint:
    'The role is disabled. The assignment itself is still active and is not shown as revoked.',

  userAuthorizationUsersReadDescription:
    'This account does not have management.user.read, so the user record and related authorization pages are not requested.',
  userRolesTitle: 'User roles',
  userRolesNoReadTitle: 'User roles cannot be read',
  userRolesNoReadDescription:
    'This account does not have management.role_assignment.read, so role assignments were not requested.',
  userRolesStepUpNote:
    'Stronger authentication is required before assigning or revoking roles for this user.',
  userRolesListTitle: 'Roles',
  userRolesListDescription: 'Roles assigned directly or inherited through groups',
  userRolesLoading: 'Loading user roles…',
  userRolesEmptyTitle: 'No roles',
  userRolesEmptyFilteredDescription: 'No roles match the selected filters',
  userRolesTableLabel: 'User roles',
  userRolesColumnRole: 'Role',
  userRolesColumnStatus: 'Status',
  userRolesColumnSource: 'Source',
  userRolesInheritedNotRevocable: 'Remove in the group',
  userRolesColumnCreated: 'Granted',
  userRolesColumnActions: 'Actions',
  userRolesPagination: 'User role pagination',
  userRolesNoWritePermission: 'No assignment write permission',
  userRolesAssignAction: 'Assign roles',
  userRolesAssignTitle: 'Assign roles to this user',
  userRolesAssignDescription: 'Choose one or more roles to assign to {user}.',
  userRolesSearchRoles: 'Search roles',
  userRolesSearchAction: 'Search',
  userRolesNoCandidates: 'No roles match this search.',
  userRolesSelectRoleRequired: 'Choose at least one role.',
  userRolesAssignConfirm: 'Assign roles',
  userRolesAssignedTitle: 'Roles assigned',
  userRolesAssignedDescription:
    'The user’s role assignments were refreshed from the server.',
  userRolesAssignedToast: 'Roles assigned',
  userRolesAssignedCommitted:
    '{count, plural, one {# new assignment created} other {# new assignments created}}.',
  userRolesRevokeAction: 'Revoke',
  userRolesRevokeFor: 'Revoke {role} from this user',
  userRolesRevokeTitle: 'Revoke this role assignment?',
  userRolesRevokeDescription:
    'Revoke {role} from this user. The assignment remains in history, and assigning the role again creates a new one.',
  userRolesRevokeConfirm: 'Revoke role',
  userRolesRevokedTitle: 'Role assignment revoked',
  userRolesRevokedDescription:
    'The role assignments were refreshed from the server and history remains visible.',
  userRolesRevokedToast: 'Role revoked',
  userRolesRevokedCommitted:
    '{count, plural, one {# assignment revoked} other {# assignments revoked}}.',

  userPermissionsTitle: 'Permissions',
  userPermissionsDescription:
    'Inspect this user’s effective permission sources for one API resource.',
  userPermissionsNoReadTitle: 'Effective permissions cannot be read',
  userPermissionsNoReadDescription:
    'This account does not have management.role_assignment.read, so effective permissions were not requested.',
  userPermissionsScopeBoundary: 'Client and token scope limits also apply',
  userPermissionsResourceTitle: 'API resource',
  userPermissionsResourceDescription:
    'Choose the resource whose effective permissions you want to inspect.',
  userPermissionsResourceSearch: 'Search resources',
  userPermissionsResourceSearchAction: 'Search',
  userPermissionsResourceLoadFailed:
    'The resource list could not be loaded. Enter a resource ID instead.',
  userPermissionsResourceLabel: 'Resource',
  userPermissionsResourceIdLabel: 'Resource ID',
  userPermissionsResourceIdDescription:
    'Resource names require management.resource.read. You can still inspect a resource by ID.',
  userPermissionsResourceUse: 'Use resource',
  userPermissionsResourceFallback: 'Resource {id}',
  userPermissionsSelectResourceTitle: 'Select an API resource',
  userPermissionsSelectResourceDescription:
    'Effective permissions are calculated for one API resource at a time.',
  userPermissionsEffectiveDescription:
    'Explicit permissions and every direct role assignment or group role source that contributes them.',
  userPermissionsPagination: 'Effective permission pagination',
  userPermissionsBoundaryTitle: 'Effective permission boundary',
  userPermissionsBoundaryDescription:
    'API access requires the matching effective permission and token scope, the correct resource, and the required authentication level.',
  userPermissionsSourceDetails: 'Relationship identifiers',
  userPermissionsLoading: 'Loading effective permissions…',
  userPermissionsEmptyTitle: 'No effective permissions',
  userPermissionsEmptyFilteredTitle: 'No permissions from this source',
  userPermissionsEmptyDescription:
    'No active direct or group role assignment currently grants a permission on this resource.',
  userPermissionsPartialTitle:
    'Some effective permission data could not be loaded',
  userPermissionsPartialDescription:
    'The permission rows remain usable, but the server returned one or more errors.',
  userPermissionsTableLabel: 'Effective permissions',
  userPermissionsColumnPermission: 'Permission',
  userPermissionsColumnScope: 'Scope',
  userPermissionsColumnSources: 'Permission sources',
  userPermissionsSourcesDirect: 'Direct role assignments',
  userPermissionsSourcesGroups: 'Group-derived sources',
  userPermissionsGroupLabel: 'Group',
  userPermissionsGroupRoleLabel: 'Role',
  userPermissionsGroupIdLabel: 'Group ID',
  userPermissionsGroupRoleIdLabel: 'Role ID',
  userPermissionsGroupMembershipIdLabel: 'Membership ID',
  userPermissionsGroupHidden:
    'Group display names require management.group.read.',

  userGroupsTitle: 'User groups',
  userGroupsDescription:
    'Review the groups this user belongs to and manage their memberships.',
  userGroupsNoGroupsReadTitle: 'Group records cannot be read',
  userGroupsNoGroupsReadDescription:
    'You do not have permission to view groups.',
  userGroupsNoMembershipsReadTitle: 'Group memberships cannot be read',
  userGroupsNoMembershipsReadDescription:
    'You do not have permission to view this user’s group memberships.',
  userGroupsNoWritePermission:
    'You can view group memberships but cannot change them',
  userGroupsNoWriteDescription:
    'You can view memberships but cannot change them.',
  userGroupsWriteStepUpNote:
    'Your selected group is kept. After verifying, return and submit again; the change is never replayed automatically.',
  userGroupsWriteStepUpHint:
    'Complete stronger authentication to change group memberships.',
  userGroupsListTitle: 'Groups',
  userGroupsListDescription: 'Groups this user belongs to',
  userGroupsSearchLabel: 'Search groups',
  userGroupsSearchPlaceholder: 'Group name',
  userGroupsSearchAction: 'Search',
  userGroupsTableLabel: 'User group memberships',
  userGroupsLoading: 'Loading user group memberships…',
  userGroupsColumnGroup: 'Group',
  userGroupsColumnKind: 'Kind',
  userGroupsColumnStatus: 'Status',
  userGroupsColumnVersion: 'Version',
  userGroupsColumnActions: 'Actions',
  userGroupsPagination: 'User group membership pagination',
  userGroupsPageSummary:
    '{count, plural, one {# group on this page} other {# groups on this page}}',
  userGroupsEmptyTitle: 'No group memberships',
  userGroupsEmptyDescription:
    'This user does not currently belong to any group.',
  userGroupsEmptyFilteredTitle: 'No group memberships match this search',
  userGroupsEmptyFilteredDescription:
    'Change the search to see other group memberships.',
  userGroupsAddAction: 'Add to group',
  userGroupsAddTitle: 'Add this user to a group',
  userGroupsAddDescription: 'Search for a group to add {user}.',
  userGroupsAddResultsLabel: 'Group search results',
  userGroupsAddSelectedGroup: 'Selected group: {group}',
  userGroupsAddNoCandidates: 'No groups match this search.',
  userGroupsSelectGroupRequired: 'Select a group to add this user to.',
  userGroupsVersionUnavailable:
    'The selected group version is unavailable. Reload the group search and select the group again.',
  userGroupsAddConfirm: 'Add to group',
  userGroupsAddedTitle: 'User added to a group',
  userGroupsAddedDescription:
    'The group memberships were refreshed from the server.',
  userGroupsAddedToast: 'User added to group',
  userGroupsAddedCommitted: 'User added to the group.',
  userGroupsRemoveAction: 'Remove',
  userGroupsRemoveTitle: 'Remove this group membership?',
  userGroupsRemoveDescription:
    'Remove {user} from “{group}”? The membership is revoked and authorization granted through this group stops immediately.',
  userGroupsRemoveFor: 'Remove {user} from {group}',
  userGroupsRemoveConfirm: 'Remove membership',
  userGroupsRemovedTitle: 'Group membership removed',
  userGroupsRemovedToast: 'Group membership removed',
  userGroupsRemovedCommitted: 'User removed from the group.',
  userGroupsConflictTitle: 'The group changed while you were working',
  userGroupsConflictDescription:
    'Reload the latest group version before trying again. The action was not replayed.',

  groupsTitle: 'Groups',
  groupsDescription:
    'Browse groups, manage their membership, and link their roles.',
  groupsNewTitle: 'New group',
  groupsNewDescription:
    'Create a group with localized names. Members and roles are managed separately.',
  groupsNewAction: 'New group',
  backToGroups: 'Back to groups',
  groupsTableLabel: 'Groups',
  groupsTableLoading: 'Loading groups…',
  groupsColumnGroup: 'Group',
  groupsColumnKind: 'Kind',
  groupsColumnStatus: 'Status',
  groupsColumnCreated: 'Created',
  groupsColumnUpdated: 'Updated',
  groupsColumnActions: 'Actions',
  groupsViewAction: 'View details',
  groupsViewFor: 'View details for {name}',
  groupsEnabled: 'Enabled',
  groupsDisabled: 'Disabled',
  groupsBuiltIn: 'Built in',
  groupsCustom: 'Custom',
  groupsPaginationLabel: 'Group list pagination',
  groupsPageSummary:
    '{count, plural, one {# group on this page} other {# groups on this page}}',
  groupsPartialTitle: 'Some group data could not be loaded',
  groupsPartialDescription:
    'The page remains usable, but the server returned one or more errors.',
  groupsEmptyTitle: 'No groups yet',
  groupsEmptyDescription: 'This instance does not have any groups to display.',
  groupsNoResultsTitle: 'No groups match these filters',
  groupsNoResultsDescription:
    'Adjust or reset the filters to see other groups.',
  groupsClearFilters: 'Clear filters',
  groupsFiltersTitle: 'Group filters',
  groupsFilterSearchLabel: 'Search',
  groupsFilterSearchPlaceholder: 'Name',
  groupsFilterEnabledLabel: 'Status',
  groupsFilterAny: 'Any',
  groupsFilterEnabledOnly: 'Enabled only',
  groupsFilterDisabledOnly: 'Disabled only',
  groupsFilterOrderLabel: 'Order',
  groupsOrderCreatedDesc: 'Newest first',
  groupsOrderCreatedAsc: 'Oldest first',
  groupsApplyFilters: 'Apply filters',
  groupsResetFilters: 'Reset filters',
  groupsNoReadTitle: 'Group records cannot be read',
  groupsNoReadDescription: 'You do not have permission to view groups.',
  groupsNoWritePermission: 'You can view this group but cannot change it',
  groupsNoStatePermission:
    'This account can view this group but cannot change its state.',
  groupsCreateNoPermissionTitle: 'You cannot create groups',
  groupsCreateNoPermissionDescription:
    'You do not have permission to create groups.',
  groupsCreateWriteOnlyTitle: 'The group was created but cannot be viewed',
  groupsCreateWriteOnlyDescription:
    'The group was created with ID {groupId}. This account cannot read group records, so no group details are shown.',
  groupsCreateAnother: 'Create another group',
  groupsCreateSuccessToast: 'Group created',
  groupsCreateCommitted: 'Group created.',
  groupsCreatePending: 'Creating group…',
  groupsCreateAction: 'Create group',
  groupsSectionNames: 'Display names',
  groupsSectionNamesDescription:
    'Provide a default name and optional translations for each viewing language.',
  groupsSectionDescriptions: 'Descriptions',
  groupsSectionDescriptionsDescription:
    'Optional localized descriptions shown alongside the group name.',
  groupsNameRequired: 'Enter a default name.',
  groupsNoReadAfterCreateTitle: 'Write-only group access',
  groupsNoReadAfterCreateDescription:
    'This account can create a group but cannot read group records. Only the new group ID and version will be shown after creation.',
  groupsFormStepUpNote:
    'Your form values are preserved. After authenticating, return here and submit again; the mutation is not replayed automatically.',
  groupsIdLabel: 'Group ID',
  groupsVersionLabel: 'Version',
  groupsCreatedAtLabel: 'Created',
  groupsUpdatedAtLabel: 'Updated',
  groupsVersionUnavailable:
    'The current version is unavailable. Reload the group before changing it.',
  groupsEditDiscard: 'Discard changes',

  groupDetailTitle: 'Group overview',
  groupDetailDescription: 'Review and update this group’s localized metadata.',
  groupMembersTitle: 'Group members',
  groupMembersDescription: 'Manage the users that belong to this group.',
  groupRolesTitle: 'Group roles',
  groupRolesDescription:
    'Manage the roles that this group grants to its members.',
  groupDetailTabsLabel: 'Group detail sections',
  groupTabOverview: 'Details',
  groupTabMembers: 'Members',
  groupTabRoles: 'Roles',
  groupBuiltInReadonlyTitle: 'Built-in group',
  groupBuiltInReadonlyDescription:
    'This group is defined by the system version. Its metadata, state, and role links cannot be changed here.',
  groupSettingsTitle: 'Details',
  groupSettingsDescription: 'Update the localized names and descriptions.',
  groupSettingsSparseHint:
    'Only changed fields are included in the update request.',
  groupSettingsSaveAction: 'Save changes',
  groupSettingsSavedToast: 'Group updated',
  groupSettingsSavedTitle: 'Group settings saved',
  groupSettingsCommitted: 'Group changes saved.',
  groupRefreshFailedTitle:
    'The change was saved but the group could not be reloaded',
  groupRefreshFailedDescription:
    'Reload the group before making another change. Do not repeat the same write.',
  groupStatusTitle: 'Group status',
  groupsEnableAction: 'Enable group',
  groupsDisableAction: 'Disable group',
  groupsEnableTitle: 'Enable this group?',
  groupsDisableTitle: 'Disable this group?',
  groupsEnableDescription:
    'The group will grant its linked roles to current members again. Revoked memberships are not restored.',
  groupsDisableDescription:
    'This group will stop granting permissions through its role links. Membership records are kept.',
  groupsEnableConfirm: 'Enable group',
  groupsDisableConfirm: 'Disable group',
  groupsEnabledToast: 'Group enabled',
  groupsDisabledToast: 'Group disabled',
  groupsStateStepUpHint:
    'Stronger authentication is required before changing group state or membership.',
  groupsDeleteAction: 'Delete group',
  groupsDeleteTitle: 'Delete this group?',
  groupsDeleteDescription:
    'Delete the group “{name}”. Its membership and role links are removed with it, and this action cannot be undone.',
  groupsDeleteConfirm: 'Delete group',
  groupsDeletedToast: 'Group deleted',

  groupMembersGroupContext: '{group}',
  groupMembersListTitle: 'Group members',
  groupMembersListDescription: 'View and manage group members.',
  groupMembersStatusFilterLabel: 'Membership status',
  groupMembersFilterAll: 'All memberships',
  groupMembersFilterActive: 'Active only',
  groupMembersFilterRemoved: 'Removed only',
  groupMembersTableLabel: 'Group members',
  groupMembersLoading: 'Loading group members…',
  groupMembersColumnMember: 'Member',
  groupMembersColumnStatus: 'Status',
  groupMembersColumnCreated: 'Created',
  groupMembersColumnActions: 'Actions',
  groupMembersPagination: 'Group member pagination',
  groupMembersPageSummary:
    '{count, plural, one {# membership on this page} other {# memberships on this page}}',
  groupMembersEmptyTitle: 'No group members',
  groupMembersEmptyDescription:
    'This group does not have any membership records yet.',
  groupMembersEmptyFilteredTitle: 'No memberships match this filter',
  groupMembersEmptyFilteredDescription:
    'Change the membership status filter to see other records.',
  groupMembersNoReadTitle: 'Group memberships cannot be read',
  groupMembersNoReadDescription:
    'You do not have permission to view group members.',
  groupMembersNoWritePermission: 'You can view members but cannot change them',
  groupMembersNoWriteDescription:
    'You can view members but cannot change them.',
  groupMembersWriteStepUpNote:
    'Your selected member is kept. After verifying, return and submit again; the change is never replayed automatically.',
  groupMembersBuiltInNote:
    'This built-in group’s metadata and role links are fixed, but its memberships can still be adjusted with the membership write permission.',
  groupMembersNoUsersReadTitle: 'User profiles are not available',
  groupMembersNoUsersReadDescription:
    'This account does not have management.user.read, so group members are not requested.',
  groupMembersGrantedByLabel: 'Granted by',
  groupMembersStatusActive: 'Active',
  groupMembersStatusRemoved: 'Removed',
  groupMembersRevokedAt: 'Removed {date}',
  groupMembersAddAction: 'Add member',
  groupMembersAddTitle: 'Add a group member',
  groupMembersAddDescription: 'Search for a user to add to “{group}”.',
  groupMembersAddResultsLabel: 'User search results',
  groupMembersAddSelectedUser: 'Selected user ID: {user}',
  groupMembersSearchUsersLabel: 'Search users',
  groupMembersSelectUserRequired: 'Select a user to add.',
  groupMembersNoCandidates: 'No users match this search.',
  groupMembersAddConfirm: 'Add member',
  groupMembersAddedToast: 'Member added',
  groupMembersAddedCommitted: 'Member added.',
  groupMembersRemoveAction: 'Remove',
  groupMembersRemoveTitle: 'Remove this group member?',
  groupMembersRemoveDescription:
    'Remove {user} from this group? The membership is revoked and its existing authorization through this group stops immediately.',
  groupMembersRemoveFor: 'Remove {user} from the group',
  groupMembersRemoveConfirm: 'Remove member',
  groupMembersRemovedToast: 'Member removed',
  groupMembersRemovedCommitted: 'Member removed.',

  groupRolesGroupContext: '{group}',
  groupRolesListTitle: 'Group role links',
  groupRolesListDescription: 'Roles granted to members of this group.',
  groupRolesSearchLabel: 'Search this page',
  groupRolesSearchPlaceholder: 'Role name or ID',
  groupRolesSearchDescription:
    'The search only filters role links already loaded on this page. Clear it or change pages to see other relations.',
  groupRolesSearchNoMatches: 'No loaded role links match this search',
  groupRolesFilterStatusLabel: 'Relation status',
  groupRolesFilterAll: 'All relations',
  groupRolesFilterActive: 'Active only',
  groupRolesFilterRemoved: 'Revoked only',
  groupRolesTableLabel: 'Group role links',
  groupRolesColumnRole: 'Role',
  groupRolesColumnRelation: 'Relation',
  groupRolesPagination: 'Group role pagination',
  groupRolesPageSummary:
    '{count, plural, one {# role relation on this page} other {# role relations on this page}}',
  groupRolesEmptyTitle: 'No role links',
  groupRolesEmptyDescription:
    'This group does not grant any roles to its members yet.',
  groupRolesEmptyFilteredTitle: 'No role links match this filter',
  groupRolesEmptyFilteredDescription:
    'Change the relation status filter to see other roles.',
  groupRolesNoReadTitle: 'Group role links cannot be read',
  groupRolesNoReadDescription:
    'You do not have permission to view group role links.',
  groupRolesBuiltInTitle: 'Built-in group role links are fixed',
  groupRolesBuiltInDescription:
    'This built-in group’s role links are defined by the system version. They are shown for reference and cannot be edited here.',
  groupRolesNoWritePermission: 'You can view role links but cannot change them',
  groupRolesNoWriteDescription:
    'You can view role links but cannot change them.',
  groupRolesWriteStepUpNote:
    'Your pending role selection is kept. After verifying, return and submit again; the change is never replayed automatically.',
  groupRolesEditAction: 'Edit role links',
  groupRolesEditTitle: 'Replace the group role set',
  groupRolesEditDescription:
    'Choose the complete set of roles that “{group}” grants to its members.',
  groupRolesEditHint:
    'Save replaces the complete active role set. Roles you clear are removed, and the change is sent only when you press Save.',
  groupRolesCurrentLoading: 'Loading the complete current role set…',
  groupRolesCurrentReload: 'Reload the role set',
  groupRolesCatalogSearchLabel: 'Search roles',
  groupRolesCatalogSearchPlaceholder: 'Role name',
  groupRolesCatalogLabel: 'Role selection results',
  groupRolesCatalogLoading: 'Loading roles…',
  groupRolesCatalogEmpty: 'No roles match this search',
  groupRolesCatalogEmptyDescription:
    'Search for another role or clear the search.',
  groupRolesSelectedCount:
    '{count, plural, one {# role selected} other {# roles selected}}',
  groupRolesNoChanges:
    'The selected roles match the current set. Select a different set to save.',
  groupRolesSaveAction: 'Save role links',
  groupRolesSavedToast: 'Group role links updated',
  groupRolesSavedCommitted:
    'Role links saved. Added: {addedCount, number}; removed: {removedCount, number}.',
} as const

export default enUS
