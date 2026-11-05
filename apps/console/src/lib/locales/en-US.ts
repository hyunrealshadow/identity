import clientsEnUS from '#/modules/client-management/clients/locales/en-US'
import resourcesEnUS from '#/modules/client-management/resources/locales/en-US'
import dashboardEnUS from '#/modules/dashboard/locales/en-US'
import userManagementEnUS from '#/modules/user-management/locales/en-US'
import roleGroupsEnUS from '#/modules/user-management/roles/locales/en-US'
import permissionsEnUS from '#/modules/client-management/resources/permissions/locales/en-US'

const shared = {
  backToDashboard: 'Back to overview',
  copyValue: 'Copy {label}',
  valueCopied: 'Copied',
  valueCopyFailed: 'Unable to copy',
  audienceLabel: 'Audience',
  permissionCodeLabel: 'Permission code',
  dateClear: 'Clear',
  tableRowActions: 'More actions',
  tableRowActionsFor: 'Actions for {name}',
  tableRefresh: 'Refresh table',
  tableLoading: 'Loading table data',
  tableGoToPage: 'Go to page {page}',
  tablePageSummary: 'Showing {count} of {total} items',
  tablePreferences: 'Table preferences',
  tableCompact: 'Compact rows',
  tableWrap: 'Wrap cell content',
  tableVisibleColumns: 'Visible columns',
  tableColumnCreated: 'Created',
  tableResetPreferences: 'Reset',
  tableCancel: 'Cancel',
  tableApplyPreferences: 'Apply',
  appTitle: 'Identity Console',
  consoleLabel: 'Console',
  navigationLabel: 'Console navigation',
  mainNavigation: 'Main navigation',
  navOverview: 'Dashboard',
  navClients: 'Clients',
  navResources: 'Resources',
  navScopes: 'Scopes',
  navUsers: 'Users',
  navGroups: 'Groups',
  navRoles: 'Roles',
  navPermissions: 'Permissions',
  navRoleAssignments: 'Role assignments',
  navEffectivePermissions: 'Effective permissions',
  navSettings: 'Settings',
  navAuditEvents: 'Audit events',
  navClientManagement: 'Client management',
  navUserManagement: 'User management',
  plannedLater: 'Planned for a later phase',
  collapseNavigation: 'Collapse navigation',
  expandNavigation: 'Expand navigation',
  openNavigation: 'Open navigation',
  closeNavigation: 'Close navigation',
  language: 'Language',
  languageBrowser: 'Browser default',
  languageEnglish: 'English',
  languageChinese: '简体中文',
  theme: 'Theme',
  themeSystem: 'Follow system',
  themeLight: 'Light',
  themeDark: 'Dark',
  accountMenu: 'Account menu',
  accountMenuFor: 'Account menu for {name}',
  accountCenter: 'Account center',
  switchAccount: 'Switch account',
  signOut: 'Sign out',
  close: 'Close',
  cancel: 'Cancel',
  confirm: 'Confirm',
  retry: 'Try again',
  refresh: 'Refresh',
  loading: 'Loading…',
  saving: 'Saving…',
  working: 'Working…',
  dismiss: 'Dismiss',
  requestId: 'Request ID',
  traceId: 'Trace ID',
  yes: 'Yes',
  no: 'No',
  unknown: 'Unknown',
  breadcrumbLabel: 'Breadcrumb',
  pageTitleFallback: 'Identity Console',
  targetLabel: 'Target',
  consequencesLabel: 'Consequences',
  errorDetailsLabel: 'Error details',

  localizedName: 'Name',
  localizedDescription: 'Description',
  localizedDefault: 'Default',
  localizedTranslations: 'Translations (optional)',
  localizedDefaultRequired: 'Enter a default name',
  localizedLanguage: 'Language',
  localizedTranslationInLocale: '{label} ({locale})',
  localizedTranslationsFilled: '{filled} of {total} translations filled',
  localizedAddTranslation: 'Add translation',
  localizedRemoveTranslation: 'Remove translation',
  localizedRemoveTranslationFor: 'Remove translation for {locale}',
  localizedTranslationRemoved: 'Removed {locale}.',
  localizedUndoRemove: 'Undo',
  localizedChooseLanguage: 'Choose language',
  localizedSearchLanguages: 'Search languages…',
  localizedNoLanguages: 'No available languages found.',
  localizedCancel: 'Cancel',
  localizedMaxTranslations: 'You can add up to {max} translations.',

  startupLoading: 'Loading console configuration…',
  startupConfigTitle: 'Console configuration is unavailable',
  startupConfigDescription:
    'The console cannot start because its public configuration could not be loaded or validated.',
  startupConfigFetch: 'The public configuration could not be fetched.',
  startupConfigInvalid:
    'The public configuration is missing required values or contains invalid URLs or scopes.',
  startupConfigRetry: 'Reload the console',

  authCompletingTitle: 'Completing sign-in',
  authCompletingDescription:
    'Validating the authorization response and establishing this console session.',
  authFailedTitle: 'Sign-in could not be completed',
  authFailedDescription:
    'No tokens were stored. Start sign-in again to create a new authorization request.',
  authMissingTransaction:
    'The sign-in attempt is missing or was already used. Start sign-in again.',
  authExpiredTransaction: 'The sign-in attempt expired. Start sign-in again.',
  authInvalidTransaction:
    'The saved sign-in attempt is invalid. Start sign-in again.',
  authStateMismatch:
    'The authorization response state does not match this sign-in attempt.',
  authNonceMismatch:
    'The identity token nonce does not match this sign-in attempt.',
  authIssuerMismatch:
    'The identity provider issuer did not match the configured issuer.',
  authCallbackMismatch:
    'The authorization response did not arrive at the configured callback path.',
  authDiscoveryFailed:
    'The identity provider metadata could not be loaded or validated.',
  authExchangeFailed:
    'The authorization code could not be exchanged for tokens.',
  authClaimsInvalid: 'The identity token claims are incomplete or invalid.',
  authTokenResponseInvalid:
    'The token response is missing a usable access token or expiry.',
  authRetry: 'Start sign-in again',
  authBackToConsole: 'Return to console',
  signedOutTitle: 'Signed out',
  signedOutDescription:
    'The in-memory tokens and page data for this console tab were cleared.',
  signedOutSsoNote:
    'If you chose single sign-out, the Identity provider session was also ended. Signing in again may ask for credentials.',
  signInAgain: 'Sign in again',
  signOutTitle: 'Sign out of the console?',
  signOutDescription:
    'Choose whether to end only this console session or also end the Identity single sign-on session.',
  signOutLocalTitle: 'Console only',
  signOutLocalDescription:
    'Clears tokens and page data in this tab. Your Identity single sign-on session remains available.',
  signOutSsoTitle: 'Single sign-out',
  signOutSsoDescription:
    'Clears this console and asks Identity to end the single sign-on session for this browser.',
  signOutLocalAction: 'Sign out of console only',
  signOutSsoAction: 'Sign out of Identity too',
  signOutSsoUnavailable:
    'The identity provider did not publish a logout endpoint, so single sign-out is unavailable.',
  signOutPending: 'Signing out…',
  sessionExpiredTitle: 'This console session expired',
  sessionExpiredDescription:
    'Your tokens are no longer valid. Sign in again to continue from this page.',
  sessionExpiredAction: 'Sign in again',
  authLoadingDescription: 'Redirecting to Identity to authorize this console.',
  authReauthenticatingTitle: 'Signing in again',
  authReauthenticatingDescription:
    'A fresh sign-in is required. Your draft will be kept.',
  authPopupLoadingTitle: 'Signing in…',
  authPopupBlockedTitle: 'Complete sign-in in a new window',
  authPopupBlockedDescription:
    'The browser blocked the verification window. Continue verification to open it, or continue in this tab.',
  authPopupContinue: 'Continue verification',
  authPopupContinueInTab: 'Continue in this tab',
  authPopupFailedTitle: 'Reauthentication failed',
  authPopupFailedDescription:
    'Your current session is still available. Try again when ready.',
  authRecoveryTitle: 'Unable to restore access',
  authRecoveryDescription:
    'Access is still unavailable after sign-in. Try again or contact an administrator.',
  authReauthenticationLoopDescription:
    'Access is still unavailable after sign-in. Please try again.',

  errorTitle: 'Something went wrong',
  errorDescriptionFallback: 'The request could not be completed. Try again.',
  networkErrorTitle: 'Identity could not be reached',
  networkErrorDescription:
    'The request did not reach the server. Check your connection, then try again.',
  httpErrorTitle: 'The server rejected the request',
  httpErrorDescription:
    'The server returned an unexpected response. The request was not retried.',
  invalidResponseTitle: 'The response could not be read',
  invalidResponseDescription:
    'The server response was not valid JSON or did not match the expected GraphQL response shape.',
  unauthorizedTitle: 'Authentication is required',
  unauthorizedDescription:
    'The console session is missing or no longer valid. Sign in again to continue.',
  forbiddenTitle: 'You do not have permission',
  forbiddenDescription:
    'This account is not allowed to read or change this resource.',
  notFoundTitle: 'Not found',
  notFoundDescription:
    'The requested resource does not exist or is no longer available.',
  partialTitle: 'Some data could not be loaded',
  partialDescription:
    'The response contains usable data and one or more errors. Review the details below.',
  conflictTitle: 'The data changed while you were editing',
  conflictDescription:
    'Reload the latest values and submit your changes again.',
  stepUpTitle: 'Stronger authentication is required',
  stepUpDescription:
    'Identity requires a new authentication step before this action can continue. Nothing was replayed automatically.',
  stepUpAcr: 'Required authentication context',
  stepUpMaxAge: 'Maximum authentication age (seconds)',
  stepUpScopes: 'Required scopes',
  stepUpPrompt: 'The provider may ask you to sign in again.',
  stepUpAction: 'Authenticate again',
  stepUpNoReplay:
    'After authenticating, review the form and submit the action again.',
  fieldErrorsTitle: 'Check the highlighted fields',
  errorRequestCorrelation:
    'Include this request identifier if you contact support.',
  goHome: 'Go to overview',
  instanceName: 'Instance name',
  instanceEnvironment: 'Environment',
  accountAvatarLabel: 'Avatar for {name}',
} as const

const enUS = {
  ...shared,
  ...dashboardEnUS,
  ...userManagementEnUS,
  ...roleGroupsEnUS,
  ...permissionsEnUS,
  ...resourcesEnUS,
  ...clientsEnUS,
} as const

export default enUS
