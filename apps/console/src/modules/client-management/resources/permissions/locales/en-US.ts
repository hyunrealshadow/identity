const enUS = {
  permissionsTitle: 'Permissions',
  permissionsDescription:
    'Browse, create, and manage explicit API permissions in this instance.',
  permissionsNewTitle: 'New permission',
  permissionsNewDescription: 'Add a permission to this resource.',
  permissionsNewAction: 'New permission',
  permissionsDetailTitle: 'Permission details',
  permissionsDetailDescription:
    'Review this permission, its localized display text, and its enabled state.',
  backToPermissions: 'Back to permissions',
  permissionsTableLabel: 'Permissions',
  permissionsTableLoading: 'Loading permissions…',
  permissionsColumnPermission: 'Permission',
  permissionsColumnResource: 'API resource',
  permissionsColumnScope: 'Scope',
  permissionsColumnStatus: 'Status',
  permissionsColumnActions: 'Actions',
  permissionsViewAction: 'View details',
  permissionsViewFor: 'View details for {name}',
  permissionsEnabled: 'Enabled',
  permissionsDisabled: 'Disabled',
  permissionsPaginationLabel: 'Permission list pagination',
  permissionsPageSummary:
    '{count, plural, one {# permission on this page} other {# permissions on this page}}',
  permissionsPartialTitle: 'Some permission data could not be loaded',
  permissionsPartialDescription:
    'The page remains usable, but the server returned one or more errors.',
  permissionsEmptyTitle: 'No permissions yet',
  permissionsEmptyDescription:
    'This instance does not have any permissions to display.',
  permissionsNoResultsTitle: 'No permissions match these filters',
  permissionsNoResultsDescription:
    'Adjust or reset the filters to see other permissions.',
  permissionsClearFilters: 'Clear filters',
  permissionsFiltersTitle: 'Permission filters',
  permissionsFilterSearchLabel: 'Search',
  permissionsFilterSearchPlaceholder: 'Permission code',
  permissionsFilterResourceLabel: 'API resource',
  permissionsFilterAnyResource: 'Any resource',
  permissionsFilterBuiltInLabel: 'Definition type',
  permissionsFilterAny: 'Any',
  permissionsFilterBuiltInOnly: 'Built-in only',
  permissionsFilterCustomOnly: 'Custom only',
  permissionsFilterStatusLabel: 'Status',
  permissionsFilterEnabled: 'Enabled only',
  permissionsFilterDisabled: 'Disabled only',
  permissionsFilterOrderLabel: 'Order',
  permissionsOrderCodeAsc: 'Code A-Z',
  permissionsOrderCodeDesc: 'Code Z-A',
  permissionsOrderCreatedDesc: 'Newest first',
  permissionsOrderCreatedAsc: 'Oldest first',
  permissionsApplyFilters: 'Apply filters',
  permissionsResetFilters: 'Reset filters',
  permissionsResourceOptionsFailed: 'API resource options could not be loaded.',
  permissionsResourceOptionsFailedTitle: 'Resource filter unavailable',
  permissionsScopeOptionsFailed: 'Scope options could not be loaded.',
  permissionsScopeOptionsFailedTitle: 'Scope selection unavailable',
  permissionsResourceUnavailable: 'Resource unavailable',
  permissionsScopeUnavailable: 'Scope unavailable',
  permissionsNoReadTitle: 'Permission records cannot be read',
  permissionsNoReadWriteOnlyDescription:
    'You do not have permission to view the permission directory.',
  permissionsCreateNoPermissionTitle: 'You cannot create permissions',
  permissionsCreateNoPermissionDescription:
    'You do not have permission to create permissions.',
  permissionsCreateWriteOnlyTitle:
    'The permission was created but cannot be viewed',
  permissionsCreateWriteOnlyDescription:
    'The permission was created with ID {permissionId}. This account cannot read permission records, so no details are shown.',
  permissionsCreateAnother: 'Create another permission',
  permissionsIdLabel: 'Permission ID',
  permissionsVersionLabel: 'Version',
  permissionsCreatedAtLabel: 'Created',
  permissionsUpdatedAtLabel: 'Updated',
  permissionsSectionIdentity: 'Permission identity',
  permissionsSectionIdentityDescription:
    'Enter a code unique within this resource.',
  permissionsFieldResource: 'API resource',
  permissionsFieldResourceDescription:
    'The API resource this permission protects.',
  permissionsFieldScope: 'Scope',
  permissionsFieldScopeDescription:
    'The registered scope associated with this permission.',
  permissionsSelectResourcePlaceholder: 'Select an API resource',
  permissionsSelectScopePlaceholder: 'Select a scope',
  permissionsFieldCode: 'Code',
  permissionsFieldCodeDescription:
    'Unique within this resource. Not translated.',
  permissionsFieldDescription: 'Description',
  permissionsCodeRequired: 'Enter a permission code.',
  permissionsResourceRequired: 'Select an API resource.',
  permissionsScopeRequired: 'Select a scope.',
  permissionsNoResourcesReadTitle: 'API resources cannot be selected',
  permissionsNoResourcesReadDescription:
    'You need permission to view API resources before selecting one.',
  permissionsNoScopesReadTitle: 'Scopes cannot be selected',
  permissionsNoScopesReadDescription:
    'You need permission to view scopes before selecting one.',
  permissionsMetadataSectionTitle: 'Localized display text',
  permissionsMetadataSectionDescription:
    'Provide a default name. Translations and descriptions are optional.',
  permissionsMetadataNameRequired: 'Enter a default name.',
  permissionsMetadataNotSet: 'Not provided',
  permissionsCreateAction: 'Create permission',
  permissionsCreatePending: 'Creating permission…',
  permissionsCreateSuccessToast: 'Permission created',
  permissionsCreateCommitted: 'Permission created.',
  permissionsFormStepUpNote:
    'Your form values are preserved. After authenticating, return here and submit again; the mutation is not replayed automatically.',
  permissionsStepUpNote:
    'After authenticating, return to this page and continue. No action was replayed automatically.',
  permissionSettingsTitle: 'Permission settings',
  permissionSettingsDescription: 'Permission code and localized display text.',
  permissionSettingsSparseHint:
    'Only changed values are included in the update request.',
  permissionSettingsSaveAction: 'Save changes',
  permissionSettingsSavedToast: 'Permission updated',
  permissionSettingsSavedTitle: 'Permission settings saved',
  permissionSettingsCommitted: 'Permission changes saved.',
  permissionRefreshFailedTitle:
    'The change was saved but the permission could not be reloaded',
  permissionRefreshFailedDescription:
    'Reload the permission before making another change. Do not repeat the same write.',
  permissionsVersionUnavailable:
    'The current version is unavailable. Reload the permission before changing it.',
  permissionsEditDiscard: 'Discard changes',
  permissionsReadOnlyTitle: 'Read-only permission',
  permissionsReadOnlyHint:
    'This account can review this custom permission but cannot change it.',
  permissionsWriteStepUpHint:
    'Stronger authentication is required before changing this permission.',
  permissionsNoWriteDescription:
    'You can view this permission but cannot change it.',
  permissionsBuiltInReadonlyTitle: 'Built-in permission definition',
  permissionsBuiltInReadonlyDescription:
    'This permission’s definition, localized text, and enabled state are fixed by the system. It is shown for review and cannot be edited here.',
  permissionsBuiltInStateReadonly:
    'The enabled state of a built-in permission is fixed by the system.',
  permissionsStatusTitle: 'Permission status',
  permissionsNoStatePermission:
    'This account can view this permission but cannot change its state.',
  permissionsEnableAction: 'Enable permission',
  permissionsDisableAction: 'Disable permission',
  permissionsEnableTitle: 'Enable this permission?',
  permissionsDisableTitle: 'Disable this permission?',
  permissionsEnableDescription:
    'The permission becomes available for new role assignments and authorization checks.',
  permissionsDisableDescription:
    'This permission stops granting access. Existing role relationships are kept.',
  permissionsEnableConfirm: 'Enable permission',
  permissionsDisableConfirm: 'Disable permission',
  permissionsEnabledToast: 'Permission enabled',
  permissionsDisabledToast: 'Permission disabled',
  permissionsConflictTitle: 'The permission changed while you were working',
  permissionsConflictDescription:
    'Reload the latest version before trying again. The action was not replayed.',
  permissionsRolesTitle: 'Roles using this permission',
  permissionsRolesDescription: 'View the roles that include this permission.',
  permissionsRolesReadRequired:
    'You do not have permission to view related roles.',
  permissionsRolesEmptyTitle: 'No roles use this permission',
} as const

export default enUS
