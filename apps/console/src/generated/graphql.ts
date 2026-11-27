/* eslint-disable */
/** Internal type. DO NOT USE DIRECTLY. */
type Exact<T extends { [key: string]: unknown }> = { [K in keyof T]: T[K] };
/** Internal type. DO NOT USE DIRECTLY. */
export type Incremental<T> = T | { [P in keyof T]?: P extends ' $fragmentName' | '__typename' ? T[P] : never };
import type { DocumentTypeDecoration } from '@graphql-typed-document-node/core';
/** Register a JWKS URI for `private_key_jwt`. Its keys refresh from the URI. */
export type AddClientJwksUriInput = {
  clientId: string | number;
  clientMutationId?: string | null | undefined;
  expectedVersion: string;
  jwksUri: string;
  reason?: string;
};

/** Register a public key for `private_key_jwt`. */
export type AddClientPublicKeyInput = {
  clientId: string | number;
  clientMutationId?: string | null | undefined;
  expectedVersion: string;
  /** Required unless `key` is a certificate, whose own expiry is used. */
  expiresAt?: string | null | undefined;
  /** A PEM public key, a PEM certificate or a single public JWK. */
  key: string;
  reason?: string;
};

export type AddGroupMemberInput = {
  clientMutationId?: string | null | undefined;
  expectedVersion: string;
  groupId: string | number;
  reason?: string;
  userId: string | number;
};

export type AssignUserRolesInput = {
  clientMutationId?: string | null | undefined;
  expectedUserVersion: string;
  reason?: string;
  roleIds: Array<string | number>;
  userId: string | number;
};

/** A stable public audit action, named object first, then verb. */
export type AuditAction =
  | 'ACCESS_TOKEN_REVOKE'
  | 'ACCOUNT_CREDENTIAL_REPLACE'
  | 'ACCOUNT_EMAIL_VERIFY'
  | 'ACCOUNT_IDENTIFIER_UPDATE'
  | 'ACCOUNT_INVITATION_ACCEPT'
  | 'ACCOUNT_LOCK'
  | 'ACCOUNT_PASSKEY_ADD'
  | 'ACCOUNT_PASSKEY_REMOVE'
  | 'ACCOUNT_PASSKEY_UPDATE'
  | 'ACCOUNT_PASSWORD_CHANGE'
  | 'ACCOUNT_PASSWORD_RESET'
  | 'ACCOUNT_PROFILE_UPDATE'
  | 'ACCOUNT_RECOVERY_CODE_REGENERATE'
  | 'ACCOUNT_REGISTER'
  | 'ACCOUNT_TOTP_DISABLE'
  | 'ACCOUNT_TOTP_ENABLE'
  | 'CLIENT_AUTHENTICATE'
  | 'CLIENT_CREATE'
  | 'CLIENT_CREDENTIAL_REVOKE'
  | 'CLIENT_DELETE'
  | 'CLIENT_DISABLE'
  | 'CLIENT_ENABLE'
  | 'CLIENT_JWKS_URI_SET'
  | 'CLIENT_PUBLIC_KEY_ADD'
  | 'CLIENT_REGISTER'
  | 'CLIENT_REGISTRATION_DELETE'
  | 'CLIENT_REGISTRATION_UPDATE'
  | 'CLIENT_SCOPE_UPDATE'
  | 'CLIENT_SECRET_CREATE'
  | 'CLIENT_SECRET_ROTATE'
  | 'CLIENT_UPDATE'
  | 'CONSENT_DENY'
  | 'CONSENT_GRANT'
  | 'DEVICE_APPROVE'
  | 'DEVICE_DENY'
  | 'DEVICE_REVOKE'
  | 'GROUP_CREATE'
  | 'GROUP_DELETE'
  | 'GROUP_DISABLE'
  | 'GROUP_ENABLE'
  | 'GROUP_MEMBER_ADD'
  | 'GROUP_MEMBER_REMOVE'
  | 'GROUP_ROLE_UPDATE'
  | 'GROUP_UPDATE'
  | 'KEY_CREATE'
  | 'KEY_REVOKE'
  | 'KEY_ROTATE'
  | 'RESOURCE_CREATE'
  | 'RESOURCE_DISABLE'
  | 'RESOURCE_ENABLE'
  | 'RESOURCE_UPDATE'
  | 'ROLE_CREATE'
  | 'ROLE_DISABLE'
  | 'ROLE_ENABLE'
  | 'ROLE_PERMISSION_UPDATE'
  | 'ROLE_UPDATE'
  | 'SCOPE_CREATE'
  | 'SCOPE_DISABLE'
  | 'SCOPE_ENABLE'
  | 'SCOPE_UPDATE'
  | 'SESSION_REAUTHENTICATE'
  | 'SESSION_REUSE'
  | 'SESSION_REVOKE'
  | 'SETTING_AUTHENTICATION_UPDATE'
  | 'SETTING_EMAIL_POLICY_UPDATE'
  | 'SETTING_EMAIL_TEMPLATE_UPDATE'
  | 'SETTING_EMAIL_UPDATE'
  | 'SETTING_PROTOCOL_UPDATE'
  | 'SETTING_SESSION_UPDATE'
  | 'SIGN_IN'
  | 'TOKEN_REPLAY'
  | 'TOKEN_REVOKE'
  | 'USER_CREATE'
  | 'USER_DELETE'
  | 'USER_DISABLE'
  | 'USER_ENABLE'
  | 'USER_INVITE'
  | 'USER_MFA_RESET'
  | 'USER_PASSWORD_RESET'
  | 'USER_ROLE_GRANT'
  | 'USER_ROLE_REVOKE'
  | 'USER_SESSION_REVOKE'
  | 'USER_UNLOCK'
  | 'USER_UPDATE';

/** Who performed the action. */
export type AuditActorKind =
  | 'ANONYMOUS'
  | 'CLIENT'
  | 'SYSTEM'
  | 'USER';

/** How a person authenticated. */
export type AuditAuthMethod =
  | 'OTP'
  | 'PASSKEY'
  | 'PASSWORD'
  | 'RECOVERY_CODE';

/** Which audit log an event belongs to. */
export type AuditCategory =
  | 'ACCOUNT'
  | 'AUTHORIZATION'
  | 'MANAGEMENT'
  | 'SIGN_IN';

export type AuditChangeKind =
  /** A secret changed; its values are never recorded. */
  | 'REDACTED'
  /** `added` and `removed` hold collection members. */
  | 'SET'
  /** `oldValue` and `newValue` hold the values. */
  | 'VALUE';

export type AuditEventOrder =
  | 'OCCURRED_AT_ASC'
  | 'OCCURRED_AT_DESC';

/** Why an attempt failed. */
export type AuditFailureReason =
  | 'ACCOUNT_DISABLED'
  | 'ACCOUNT_LOCKED'
  | 'INVALID_CREDENTIAL'
  | 'INVALID_OTP'
  | 'INVALID_RECOVERY_CODE'
  | 'REPLAY_DETECTED'
  | 'UNKNOWN_ACCOUNT';

/** A changed attribute of an audited object. */
export type AuditField =
  | 'ADDRESS'
  | 'BIRTHDATE'
  | 'DESCRIPTION'
  | 'DESCRIPTIONS'
  | 'EMAIL'
  | 'EMAIL_VERIFIED'
  | 'ENABLED'
  | 'FAMILY_NAME'
  | 'GENDER'
  | 'GIVEN_NAME'
  | 'LOCALE'
  | 'MEMBERS'
  | 'MIDDLE_NAME'
  | 'NAME'
  | 'NAMES'
  | 'NICKNAME'
  | 'PASSKEY'
  | 'PASSWORD'
  | 'PERMISSIONS'
  | 'PHONE_NUMBER'
  | 'PICTURE'
  | 'PREFERENCES'
  | 'PROFILE'
  | 'RECOVERY_CODES'
  | 'REQUIRED_ACTIONS'
  | 'ROLES'
  | 'SCOPES'
  | 'SETTINGS'
  | 'TIME_ZONE'
  | 'TOTP'
  | 'USERNAME'
  | 'WEBSITE';

/** Result of the audited attempt. */
export type AuditOutcome =
  | 'FAILURE'
  | 'SUCCESS';

/** Type of the object an action applies to. */
export type AuditTargetKind =
  | 'CLIENT'
  | 'DEVICE_AUTHORIZATION'
  | 'GROUP'
  | 'KEY'
  | 'PASSKEY'
  | 'RESOURCE'
  | 'ROLE'
  | 'SCOPE'
  | 'SESSION'
  | 'SETTING'
  | 'USER';

/** Where a user's role or permission comes from. */
export type AuthorizationSource =
  /** Assigned to the user directly. */
  | 'DIRECT'
  /** Inherited through an active membership in an enabled group. */
  | 'GROUP';

/**
 * Advanced OpenID Connect metadata, replaced as one unit. Omitted values
 * clear the field back to the provider default.
 */
export type ClientAdvancedSettingsInput = {
  backchannelLogoutSessionRequired?: boolean;
  backchannelLogoutUri?: string | null | undefined;
  clientUri?: string | null | undefined;
  contacts?: Array<string>;
  defaultAcrValues?: Array<string>;
  defaultMaxAge?: number | null | undefined;
  frontchannelLogoutSessionRequired?: boolean;
  frontchannelLogoutUri?: string | null | undefined;
  idTokenEncryptedResponseAlgs?: Array<string>;
  idTokenEncryptedResponseEncs?: Array<string>;
  idTokenSignedResponseAlgs?: Array<string>;
  initiateLoginUri?: string | null | undefined;
  logoUri?: string | null | undefined;
  policyUri?: string | null | undefined;
  requestObjectEncryptionAlgs?: Array<string>;
  requestObjectEncryptionEncs?: Array<string>;
  requestObjectSigningAlgs?: Array<string>;
  requestUris?: Array<string>;
  requireAuthTime?: boolean;
  sectorIdentifierUri?: string | null | undefined;
  subjectType?: ClientSubjectType;
  tokenEndpointAuthSigningAlgs?: Array<string>;
  tosUri?: string | null | undefined;
  userinfoEncryptedResponseAlgs?: Array<string>;
  userinfoEncryptedResponseEncs?: Array<string>;
  userinfoSignedResponseAlgs?: Array<string>;
};

/**
 * Token endpoint client authentication. Derived from the client's active
 * credentials and its public flow switch; it is never set directly.
 */
export type ClientAuthMethod =
  | 'CLIENT_SECRET_BASIC'
  | 'CLIENT_SECRET_JWT'
  | 'CLIENT_SECRET_POST'
  | 'NONE'
  | 'PRIVATE_KEY_JWT';

export type ClientCredentialKind =
  | 'CLIENT_SECRET'
  | 'JWKS_URI'
  | 'PUBLIC_KEY';

export type ClientFilter = {
  enabled?: boolean | null | undefined;
  /** Matches the name, or the exact client ID. */
  query?: string | null | undefined;
};

/**
 * OAuth grant type. `IMPLICIT` is shown for existing registrations only and
 * cannot be newly selected.
 */
export type ClientGrantType =
  | 'AUTHORIZATION_CODE'
  | 'CLIENT_CREDENTIALS'
  | 'DEVICE_CODE'
  | 'IMPLICIT'
  | 'REFRESH_TOKEN';

/**
 * OAuth rules for this client's authorization-code exchanges. Omitting the
 * input inherits the live global `openid_connect.oauth_version` setting.
 */
export type ClientOAuthVersion =
  | 'OAUTH_2_0'
  | 'OAUTH_2_1';

export type ClientOrder =
  | 'CREATED_AT_ASC'
  | 'CREATED_AT_DESC'
  | 'NAME_ASC'
  | 'NAME_DESC';

export type ClientPlatformInput = {
  platform: ClientPlatformType;
  redirectUris: Array<string>;
};

export type ClientPlatformType =
  | 'NATIVE'
  | 'WEB';

export type ClientScopeAssignmentInput = {
  /** Grant the scope to the client itself for client-credentials access. */
  clientGranted?: boolean;
  scopeId: string | number;
};

/** Protocol configuration, replaced as one unit. */
export type ClientSettingsInput = {
  /**
   * Lets the client authenticate without a credential (PKCE public client
   * flow); this also lists `NONE` among its token endpoint methods.
   */
  allowPublicClientFlow?: boolean;
  corsEnabled?: boolean;
  grantTypes: Array<ClientGrantType>;
  includeScopedClaimsInAccessToken?: boolean;
  includeScopedClaimsInIdToken?: boolean;
  /** Omitting this inherits the live global OAuth version. */
  oauthVersion?: ClientOAuthVersion | null | undefined;
  platforms: Array<ClientPlatformInput>;
  postLogoutRedirectUris?: Array<string>;
  requirePushedAuthorizationRequests?: boolean;
  skipConsent?: boolean;
};

/** Enable, disable or delete one client. */
export type ClientStateInput = {
  clientMutationId?: string | null | undefined;
  expectedVersion: string;
  id: string | number;
  reason?: string;
};

/** How the `sub` claim is formed for this client's users. */
export type ClientSubjectType =
  /**
   * An identifier unique to the client's sector, so separate parties cannot
   * correlate one user.
   */
  | 'PAIRWISE'
  /** The same identifier for every client. */
  | 'PUBLIC';

export type CreateClientInput = {
  clientMutationId?: string | null | undefined;
  description?: string;
  descriptions?: Array<LocalizedTextInput>;
  name: string;
  names?: Array<LocalizedTextInput>;
  reason?: string;
  settings: ClientSettingsInput;
};

export type CreateClientSecretInput = {
  clientId: string | number;
  clientMutationId?: string | null | undefined;
  expectedVersion: string;
  lifetimeDays?: number;
  reason?: string;
};

export type CreateGroupInput = {
  clientMutationId?: string | null | undefined;
  description?: string;
  descriptions?: Array<LocalizedTextInput>;
  name: string;
  names?: Array<LocalizedTextInput>;
  reason?: string;
};

export type CreateRoleInput = {
  clientMutationId?: string | null | undefined;
  description?: string;
  descriptions?: Array<LocalizedTextInput>;
  name: string;
  names?: Array<LocalizedTextInput>;
  reason?: string;
};

export type CreateScopeInput = {
  clientMutationId?: string | null | undefined;
  code: string;
  description?: string;
  descriptions?: Array<ScopeDescriptionInput> | null | undefined;
  name: string;
  names?: Array<ScopeDescriptionInput>;
  reason?: string;
  /** Every custom scope is owned by an API resource. */
  resourceId: string | number;
};

export type CreateSigningKeyInput = {
  algorithm: SigningAlgorithm;
  clientMutationId?: string | null | undefined;
  /**
   * A key the algorithm signs with, from `signingKeyAlgorithms`. Needed
   * only where it offers several (EdDSA); omitted selects its default.
   */
  keyAlgorithm?: KeyAlgorithm | null | undefined;
};

export type CreateUserInput = {
  clientMutationId?: string | null | undefined;
  email: string;
  /**
   * The initial password. Leave it out and set `sendInvitation` to let
   * the user choose their own.
   */
  password?: string | null | undefined;
  profile?: UserProfilePatchInput | null | undefined;
  reason?: string;
  /**
   * Email the user a link to set their first password instead of setting
   * one now. Needs email delivery.
   */
  sendInvitation?: boolean;
  username: string;
};

export type EffectivePermissionOrder =
  | 'CODE_ASC'
  | 'CODE_DESC';

/**
 * SMTP authentication to store. Leave a secret out to keep the stored one
 * while the method stays the same.
 */
export type EmailAuthenticationInput = {
  clientId?: string | null | undefined;
  clientSecret?: string | null | undefined;
  grant?: Xoauth2Grant | null | undefined;
  method: EmailAuthenticationMethod;
  password?: string | null | undefined;
  refreshToken?: string | null | undefined;
  scope?: string | null | undefined;
  tokenEndpoint?: string | null | undefined;
  username?: string | null | undefined;
};

export type EmailAuthenticationMethod =
  /** An unauthenticated relay. */
  | 'NONE'
  /** A username and password. */
  | 'PASSWORD'
  /** An OAuth 2.0 access token (`AUTH XOAUTH2`). */
  | 'XOAUTH2';

/** Why a queued email was given up. */
export type EmailDeliveryFailure =
  /** The mail server refused the instance's credentials. */
  | 'AUTHENTICATION_FAILED'
  /** What it carried stopped working before it could be sent. */
  | 'EXPIRED'
  /** The mail server refused the address. */
  | 'INVALID_ADDRESS'
  /** The queued message could not be read back. */
  | 'MESSAGE_UNREADABLE'
  /** Email delivery was turned off or is incomplete. */
  | 'NOT_CONFIGURED'
  /**
   * The mail server refused the message for good, for example an
   * unknown recipient.
   */
  | 'REJECTED'
  /** The stored delivery secret could not be read. */
  | 'SECRET_UNAVAILABLE'
  /** The mail server could not be reached or kept failing. */
  | 'TRANSPORT_FAILED';

/** Where a queued email stands. */
export type EmailDeliveryStatus =
  /** The mail server accepted it. */
  | 'DELIVERED'
  /** Given up; `failure` says why. */
  | 'FAILED'
  /** Waiting for, or being tried by, the delivery worker. */
  | 'QUEUED';

export type EmailTemplateContentInput = {
  html: string;
  subject: string;
};

export type EmailTemplateKind =
  /** The link that verifies an account's email address. */
  | 'EMAIL_VERIFICATION'
  /** The link that replaces a forgotten password from the sign-in flow. */
  | 'PASSWORD_RESET'
  /** The link that continues creating an account from the sign-in flow. */
  | 'REGISTRATION'
  /** The one-time code and sign-in link of email sign-in. */
  | 'SIGN_IN_CODE'
  /** The link with which an invited user sets their first password. */
  | 'USER_INVITATION';

export type EmailTemplatePreviewInput = {
  content: EmailTemplateContentInput;
  kind: EmailTemplateKind;
  /** The language previewed; omit it for the default content. */
  locale?: string | null | undefined;
  /** Sample scenario to render; omit it for the template's default scenario. */
  scenario?: EmailTemplatePreviewScenario | null | undefined;
};

/**
 * Conditional sample scenario rendered when previewing or test-sending an
 * email template.
 */
export type EmailTemplatePreviewScenario =
  /** Verifying a new email address before replacing the current one. */
  | 'EMAIL_VERIFICATION_CHANGE_ADDRESS'
  /** Verifying the account's current email address. */
  | 'EMAIL_VERIFICATION_CURRENT_ADDRESS'
  /** Existing-account notice when the email address already has an account. */
  | 'REGISTRATION_EXISTING_ACCOUNT'
  /** Registration link when the email address is not yet registered. */
  | 'REGISTRATION_NEW_ACCOUNT'
  /** Sign-in code requested directly without an application name. */
  | 'SIGN_IN_CODE_WITHOUT_APPLICATION'
  /** Sign-in code requested through an OAuth/OIDC client application. */
  | 'SIGN_IN_CODE_WITH_APPLICATION';

export type EmailTemplateTranslationInput = {
  content: EmailTemplateContentInput;
  /** Language tag. */
  locale: string;
};

export type GroupFilter = {
  builtIn?: boolean | null | undefined;
  enabled?: boolean | null | undefined;
  query?: string | null | undefined;
  roleId?: string | number | null | undefined;
  userId?: string | number | null | undefined;
};

export type GroupMembershipFilter = {
  enabled?: boolean | null | undefined;
  userId?: string | number | null | undefined;
};

export type GroupMembershipOrder =
  | 'CREATED_AT_ASC'
  | 'CREATED_AT_DESC';

export type GroupOrder =
  | 'CREATED_AT_ASC'
  | 'CREATED_AT_DESC';

export type GroupRoleFilter = {
  enabled?: boolean | null | undefined;
  roleId?: string | number | null | undefined;
};

export type GroupRoleOrder =
  | 'CREATED_AT_ASC'
  | 'CREATED_AT_DESC'
  | 'ROLE_NAME_ASC'
  | 'ROLE_NAME_DESC';

export type GroupStateInput = {
  clientMutationId?: string | null | undefined;
  expectedVersion: string;
  id: string | number;
  reason?: string;
};

/** A key type this instance generates. */
export type KeyAlgorithm =
  | 'ECDSA_P256'
  | 'ECDSA_P384'
  | 'ECDSA_P521'
  | 'ECDSA_SECP256K1'
  | 'ED448'
  | 'ED25519'
  | 'RSA_2048'
  | 'RSA_3072'
  | 'RSA_4096'
  | 'X448'
  | 'X25519';

export type KeyFilter = {
  statuses?: Array<KeyStatus> | null | undefined;
  use?: KeyUse | null | undefined;
};

export type KeyLifecycleInput = {
  clientMutationId?: string | null | undefined;
  id: string | number;
};

export type KeyStatus =
  /** Used for new signatures or new encryption. */
  | 'ACTIVE'
  | 'EXPIRED'
  /** Replaced by a successor; still verifies or decrypts until it expires. */
  | 'RETIRED'
  | 'REVOKED';

export type KeyUse =
  /** Protects sessions, tokens and cursors. */
  | 'ENCRYPTION'
  /** Signs tokens; its public part is published in the JWKS. */
  | 'SIGNING';

export type LocalizedEmailTemplateInput = {
  default: EmailTemplateContentInput;
  translations: Array<EmailTemplateTranslationInput>;
};

export type LocalizedTextInput = {
  locale: string;
  value: string;
};

export type PasswordHashingInput = {
  memoryCostKib: number;
  parallelism: number;
  timeCost: number;
};

export type RemoveGroupMemberInput = {
  clientMutationId?: string | null | undefined;
  expectedVersion: string;
  groupId: string | number;
  reason?: string;
  userId: string | number;
};

export type ResourceFilter = {
  enabled?: boolean | null | undefined;
  query?: string | null | undefined;
};

export type ResourceOrder =
  | 'CREATED_AT_ASC'
  | 'CREATED_AT_DESC'
  | 'NAME_ASC'
  | 'NAME_DESC'
  | 'URI_ASC'
  | 'URI_DESC';

export type RevokeClientCredentialInput = {
  clientId: string | number;
  clientMutationId?: string | null | undefined;
  credentialId: string | number;
  expectedVersion: string;
  reason?: string;
};

export type RevokeUserRolesInput = {
  clientMutationId?: string | null | undefined;
  expectedUserVersion: string;
  reason?: string;
  roleIds: Array<string | number>;
  userId: string | number;
};

/** Sessions of one user to revoke. */
export type RevokeUserSessionsInput = {
  clientMutationId?: string | null | undefined;
  id: string | number;
  reason?: string;
  /** Sessions to revoke; every active session when omitted. */
  sessionIds?: Array<string | number> | null | undefined;
};

export type RoleFilter = {
  builtIn?: boolean | null | undefined;
  enabled?: boolean | null | undefined;
  query?: string | null | undefined;
  /** Optional membership filter on a canonical scope identity. */
  scopeId?: string | number | null | undefined;
};

export type RoleOrder =
  | 'CREATED_AT_ASC'
  | 'CREATED_AT_DESC'
  | 'NAME_ASC'
  | 'NAME_DESC';

export type RoleStateInput = {
  clientMutationId?: string | null | undefined;
  expectedVersion: string;
  id: string | number;
  reason?: string;
};

/** Issue a new secret and revoke `credentialId` in the same change. */
export type RotateClientSecretInput = {
  clientId: string | number;
  clientMutationId?: string | null | undefined;
  credentialId: string | number;
  expectedVersion: string;
  lifetimeDays?: number;
  reason?: string;
};

export type ScopeDescriptionInput = {
  locale: string;
  value: string;
};

export type ScopeFilter = {
  apiOnly?: boolean;
  builtIn?: boolean | null | undefined;
  enabled?: boolean | null | undefined;
  /** Only concrete protocol/identity scopes such as `openid`. */
  protocolOnly?: boolean;
  query?: string | null | undefined;
  resourceId?: string | number | null | undefined;
  roleId?: string | number | null | undefined;
};

export type ScopeOrder =
  | 'CODE_ASC'
  | 'CODE_DESC'
  | 'CREATED_AT_ASC'
  | 'CREATED_AT_DESC';

export type ScopeStateInput = {
  clientMutationId?: string | null | undefined;
  expectedVersion: string;
  id: string | number;
  reason?: string;
};

export type SendTestEmailInput = {
  clientMutationId?: string | null | undefined;
  /** Language of the message. */
  locale: string;
  recipient: string;
  /** Template draft to render instead of the generic delivery test message. */
  template?: EmailTemplatePreviewInput | null | undefined;
};

export type SendUserInvitationInput = {
  clientMutationId?: string | null | undefined;
  id: string | number;
  reason?: string;
};

export type SetClientScopesInput = {
  clientId: string | number;
  clientMutationId?: string | null | undefined;
  expectedVersion: string;
  reason?: string;
  scopes: Array<ClientScopeAssignmentInput>;
};

export type SetGroupEnabledInput = {
  clientMutationId?: string | null | undefined;
  enabled: boolean;
  expectedVersion: string;
  id: string | number;
  reason?: string;
};

export type SetGroupRolesInput = {
  clientMutationId?: string | null | undefined;
  expectedVersion: string;
  groupId: string | number;
  reason?: string;
  roleIds: Array<string | number>;
};

export type SetRolePermissionsInput = {
  clientMutationId?: string | null | undefined;
  expectedVersion: string;
  permissionIds: Array<string | number>;
  reason?: string;
  roleId: string | number;
};

/** A JWA algorithm a signing key signs with. */
export type SigningAlgorithm =
  | 'ES256'
  | 'ES256K'
  | 'ES384'
  | 'ES512'
  | 'EdDSA'
  | 'PS256'
  | 'PS384'
  | 'PS512'
  | 'RS256'
  | 'RS384'
  | 'RS512';

export type SmtpSecurity =
  /** No transport security; only for a relay on a trusted network. */
  | 'NONE'
  /** A plain connection that must upgrade with STARTTLS, usually on port 587. */
  | 'START_TLS'
  /** TLS from the first byte, usually on port 465. */
  | 'TLS';

export type UnlockUserInput = {
  clientMutationId?: string | null | undefined;
  expectedVersion: string;
  id: string | number;
  reason?: string;
};

export type UpdateAuthenticationSettingsInput = {
  breachedPasswordCheckEnabled: boolean;
  clientMutationId?: string | null | undefined;
  emailSignInEnabled: boolean;
  expectedVersion: string;
  identifierEnumerationAllowed: boolean;
  lockoutDurationMinutes: number;
  maxFailedAttempts: number;
  passwordHashing: PasswordHashingInput;
  passwordHistoryCount: number;
  passwordMaxAgeDays: number;
  passwordMinLength: number;
  passwordResetEnabled: boolean;
  registrationEnabled: boolean;
};

export type UpdateClientInput = {
  /** Omitting this keeps the current advanced metadata. */
  advancedSettings?: ClientAdvancedSettingsInput | null | undefined;
  clientMutationId?: string | null | undefined;
  description?: string | null | undefined;
  descriptions?: Array<LocalizedTextInput> | null | undefined;
  expectedVersion: string;
  id: string | number;
  name?: string | null | undefined;
  names?: Array<LocalizedTextInput> | null | undefined;
  reason?: string;
  settings?: ClientSettingsInput | null | undefined;
};

export type UpdateEmailDeliverySettingsInput = {
  authentication: EmailAuthenticationInput;
  clientMutationId?: string | null | undefined;
  enabled: boolean;
  expectedVersion: string;
  host: string;
  port: number;
  security: SmtpSecurity;
  senderAddress: string;
  senderName?: string | null | undefined;
};

export type UpdateEmailPolicySettingsInput = {
  clientMutationId?: string | null | undefined;
  emailVerificationLifetimeHours: number;
  expectedVersion: string;
  loginMaxSends: number;
  passwordResetLifetimeMinutes: number;
  registrationLifetimeMinutes: number;
  resendIntervalSeconds: number;
  signInCodeLifetimeMinutes: number;
  userInvitationLifetimeDays: number;
  verificationMaxSends: number;
  verificationSendWindowHours: number;
};

/**
 * Replace one template with an operator's own, or with `content: null` use
 * the built-in template again.
 */
export type UpdateEmailTemplateInput = {
  clientMutationId?: string | null | undefined;
  content?: LocalizedEmailTemplateInput | null | undefined;
  expectedVersion: string;
  kind: EmailTemplateKind;
};

export type UpdateGroupInput = {
  clientMutationId?: string | null | undefined;
  description?: string | null | undefined;
  descriptions?: Array<LocalizedTextInput> | null | undefined;
  expectedVersion: string;
  id: string | number;
  name?: string | null | undefined;
  names?: Array<LocalizedTextInput> | null | undefined;
  reason?: string;
};

export type UpdateProtocolSettingsInput = {
  accessTokenLifetimeSeconds: number;
  authorizationCodeLifetimeSeconds: number;
  clientMutationId?: string | null | undefined;
  deviceAuthorizationPollingIntervalSeconds: number;
  deviceAuthorizationRequestLifetimeSeconds: number;
  dynamicRegistrationEnabled: boolean;
  expectedVersion: string;
  idTokenLifetimeSeconds: number;
  oauthVersion: ClientOAuthVersion;
  pushedAuthorizationRequestLifetimeSeconds: number;
  refreshTokenLifetimeDays: number;
  requirePushedAuthorizationRequests: boolean;
};

export type UpdateRoleInput = {
  clientMutationId?: string | null | undefined;
  description?: string | null | undefined;
  descriptions?: Array<LocalizedTextInput> | null | undefined;
  expectedVersion: string;
  id: string | number;
  name?: string | null | undefined;
  names?: Array<LocalizedTextInput> | null | undefined;
  reason?: string;
};

export type UpdateScopeInput = {
  clientMutationId?: string | null | undefined;
  description?: string | null | undefined;
  descriptions?: Array<ScopeDescriptionInput> | null | undefined;
  expectedVersion: string;
  id: string | number;
  name?: string | null | undefined;
  names?: Array<ScopeDescriptionInput> | null | undefined;
  reason?: string;
};

export type UpdateSessionSettingsInput = {
  clientMutationId?: string | null | undefined;
  elevatedAuthenticationLifetimeMinutes: number;
  expectedVersion: string;
  loginLifetimeMinutes: number;
  recentAuthenticationLifetimeMinutes: number;
  sessionLifetimeHours: number;
};

export type UpdateUserInput = {
  clientMutationId?: string | null | undefined;
  email?: string | null | undefined;
  /**
   * Mark the email address verified or unverified. Without it, a changed
   * address becomes unverified.
   */
  emailVerified?: boolean | null | undefined;
  expectedVersion: string;
  id: string | number;
  profile?: UserProfilePatchInput | null | undefined;
  reason?: string;
  /**
   * Replace what the next sign-in must complete; an empty list clears it.
   * Omitted, the current actions are kept.
   */
  requiredActions?: Array<UserRequiredAction> | null | undefined;
  username?: string | null | undefined;
};

export type UserFilter = {
  createdBefore?: string | null | undefined;
  createdFrom?: string | null | undefined;
  email?: string | null | undefined;
  enabled?: boolean | null | undefined;
  locked?: boolean | null | undefined;
  query?: string | null | undefined;
  username?: string | null | undefined;
};

/**
 * Stable user-management ordering. Explicit SDL names keep consumers and the
 * persisted cursor contract independent from Rust identifier conventions.
 */
export type UserOrder =
  | 'CREATED_AT_ASC'
  | 'CREATED_AT_DESC'
  | 'USERNAME_ASC'
  | 'USERNAME_DESC';

export type UserProfilePatchInput = {
  addressCountry?: string | null | undefined;
  addressFormatted?: string | null | undefined;
  addressLocality?: string | null | undefined;
  addressPostalCode?: string | null | undefined;
  addressRegion?: string | null | undefined;
  addressStreetAddress?: string | null | undefined;
  birthdate?: string | null | undefined;
  familyName?: string | null | undefined;
  gender?: string | null | undefined;
  givenName?: string | null | undefined;
  locale?: string | null | undefined;
  middleName?: string | null | undefined;
  nickname?: string | null | undefined;
  picture?: string | null | undefined;
  profile?: string | null | undefined;
  theme?: string | null | undefined;
  website?: string | null | undefined;
  zoneInfo?: string | null | undefined;
};

/** Something the user must do at their next sign-in before it completes. */
export type UserRequiredAction =
  /** Replace the password. */
  | 'CHANGE_PASSWORD';

export type UserRoleOrder =
  | 'CREATED_AT_ASC'
  | 'CREATED_AT_DESC';

export type UserStateInput = {
  clientMutationId?: string | null | undefined;
  expectedVersion: string;
  id: string | number;
  reason?: string;
};

export type Xoauth2Grant =
  /** Authenticate as the OAuth client itself. */
  | 'CLIENT_CREDENTIALS'
  /** Exchange a refresh token issued to the mailbox user. */
  | 'REFRESH_TOKEN';

export type ConsoleBootstrapQueryVariables = Exact<{ [key: string]: never; }>;


export type ConsoleBootstrapQuery = { effectivePermissions: { requestableScopes: Array<string>, grantedScopes: Array<string>, effectiveScopes: Array<string>, authentication: { acr: string | null, authTime: string | null, aal2: boolean, recent: boolean } }, instanceInfo: { name: string, environment: string, issuer: string, version: string } };

export type ConsoleAccountThemeQueryVariables = Exact<{ [key: string]: never; }>;


export type ConsoleAccountThemeQuery = { account: { id: string, theme: string | null, locale: string | null, zoneInfo: string | null } | null };

export type ConsoleClientAdvancedSettingsFieldsFragment = { frontchannelLogoutUri: string | null, frontchannelLogoutSessionRequired: boolean, backchannelLogoutUri: string | null, backchannelLogoutSessionRequired: boolean, logoUri: string | null, clientUri: string | null, policyUri: string | null, tosUri: string | null, contacts: Array<string>, subjectType: ClientSubjectType, sectorIdentifierUri: string | null, defaultMaxAge: number | null, requireAuthTime: boolean, defaultAcrValues: Array<string>, idTokenSignedResponseAlgs: Array<string>, idTokenEncryptedResponseAlgs: Array<string>, idTokenEncryptedResponseEncs: Array<string>, userinfoSignedResponseAlgs: Array<string>, userinfoEncryptedResponseAlgs: Array<string>, userinfoEncryptedResponseEncs: Array<string>, requestObjectSigningAlgs: Array<string>, requestObjectEncryptionAlgs: Array<string>, requestObjectEncryptionEncs: Array<string>, requestUris: Array<string>, tokenEndpointAuthSigningAlgs: Array<string>, initiateLoginUri: string | null };

export type ConsoleClientFieldsFragment = { id: string, name: string, description: string, builtIn: boolean, enabled: boolean, postLogoutRedirectUris: Array<string>, grantTypes: Array<ClientGrantType>, allowPublicClientFlow: boolean, requirePushedAuthorizationRequests: boolean, skipConsent: boolean, corsEnabled: boolean, oauthVersion: ClientOAuthVersion | null, includeScopedClaimsInIdToken: boolean, includeScopedClaimsInAccessToken: boolean, corsOrigins: Array<string>, version: string, createdAt: string, updatedAt: string | null, names: Array<{ locale: string, value: string }>, descriptions: Array<{ locale: string, value: string }>, platforms: Array<{ platform: ClientPlatformType, redirectUris: Array<string> }>, advancedSettings: { frontchannelLogoutUri: string | null, frontchannelLogoutSessionRequired: boolean, backchannelLogoutUri: string | null, backchannelLogoutSessionRequired: boolean, logoUri: string | null, clientUri: string | null, policyUri: string | null, tosUri: string | null, contacts: Array<string>, subjectType: ClientSubjectType, sectorIdentifierUri: string | null, defaultMaxAge: number | null, requireAuthTime: boolean, defaultAcrValues: Array<string>, idTokenSignedResponseAlgs: Array<string>, idTokenEncryptedResponseAlgs: Array<string>, idTokenEncryptedResponseEncs: Array<string>, userinfoSignedResponseAlgs: Array<string>, userinfoEncryptedResponseAlgs: Array<string>, userinfoEncryptedResponseEncs: Array<string>, requestObjectSigningAlgs: Array<string>, requestObjectEncryptionAlgs: Array<string>, requestObjectEncryptionEncs: Array<string>, requestUris: Array<string>, tokenEndpointAuthSigningAlgs: Array<string>, initiateLoginUri: string | null } };

export type ConsoleClientsQueryVariables = Exact<{
  filter?: ClientFilter | null | undefined;
  orderBy?: ClientOrder | null | undefined;
  first?: number | null | undefined;
  after?: string | null | undefined;
  last?: number | null | undefined;
  before?: string | null | undefined;
}>;


export type ConsoleClientsQuery = { clients: { totalCount: number, pageInfo: { hasNextPage: boolean, hasPreviousPage: boolean, startCursor: string | null, endCursor: string | null }, edges: Array<{ cursor: string, node: { id: string, name: string, builtIn: boolean, enabled: boolean, version: string, createdAt: string, names: Array<{ locale: string, value: string }> } }> } };

export type ConsoleClientQueryVariables = Exact<{
  id: string | number;
}>;


export type ConsoleClientQuery = { client: { id: string, name: string, description: string, builtIn: boolean, enabled: boolean, postLogoutRedirectUris: Array<string>, grantTypes: Array<ClientGrantType>, allowPublicClientFlow: boolean, requirePushedAuthorizationRequests: boolean, skipConsent: boolean, corsEnabled: boolean, oauthVersion: ClientOAuthVersion | null, includeScopedClaimsInIdToken: boolean, includeScopedClaimsInAccessToken: boolean, corsOrigins: Array<string>, version: string, createdAt: string, updatedAt: string | null, names: Array<{ locale: string, value: string }>, descriptions: Array<{ locale: string, value: string }>, platforms: Array<{ platform: ClientPlatformType, redirectUris: Array<string> }>, advancedSettings: { frontchannelLogoutUri: string | null, frontchannelLogoutSessionRequired: boolean, backchannelLogoutUri: string | null, backchannelLogoutSessionRequired: boolean, logoUri: string | null, clientUri: string | null, policyUri: string | null, tosUri: string | null, contacts: Array<string>, subjectType: ClientSubjectType, sectorIdentifierUri: string | null, defaultMaxAge: number | null, requireAuthTime: boolean, defaultAcrValues: Array<string>, idTokenSignedResponseAlgs: Array<string>, idTokenEncryptedResponseAlgs: Array<string>, idTokenEncryptedResponseEncs: Array<string>, userinfoSignedResponseAlgs: Array<string>, userinfoEncryptedResponseAlgs: Array<string>, userinfoEncryptedResponseEncs: Array<string>, requestObjectSigningAlgs: Array<string>, requestObjectEncryptionAlgs: Array<string>, requestObjectEncryptionEncs: Array<string>, requestUris: Array<string>, tokenEndpointAuthSigningAlgs: Array<string>, initiateLoginUri: string | null } } | null };

export type ConsoleClientCredentialsQueryVariables = Exact<{
  id: string | number;
}>;


export type ConsoleClientCredentialsQuery = { client: { id: string, version: string, credentials: Array<{ id: string, type: ClientCredentialKind, hint: string, expiresAt: string | null, active: boolean, createdAt: string }> } | null };

export type ConsoleClientKeyCoverageQueryVariables = Exact<{
  id: string | number;
}>;


export type ConsoleClientKeyCoverageQuery = { client: { id: string, tokenEndpointAuthMethods: Array<ClientAuthMethod>, keyCoverage: { encryptionAlgs: Array<string>, verificationAlgs: Array<string>, remoteKeys: boolean, secret: boolean } } | null };

export type ConsoleClientScopesQueryVariables = Exact<{
  id: string | number;
  orderBy?: ScopeOrder | null | undefined;
  first?: number | null | undefined;
  after?: string | null | undefined;
  last?: number | null | undefined;
  before?: string | null | undefined;
}>;


export type ConsoleClientScopesQuery = { client: { id: string, version: string, scopes: { totalCount: number, pageInfo: { hasNextPage: boolean, hasPreviousPage: boolean, startCursor: string | null, endCursor: string | null }, edges: Array<{ cursor: string, clientGranted: boolean, node: { id: string, code: string, name: string, resourceId: string | null, builtIn: boolean, enabled: boolean, names: Array<{ locale: string, value: string }> } }> } } | null };

export type ConsoleProtocolScopesQueryVariables = Exact<{
  first?: number | null | undefined;
  after?: string | null | undefined;
}>;


export type ConsoleProtocolScopesQuery = { scopes: { pageInfo: { hasNextPage: boolean, endCursor: string | null }, edges: Array<{ node: { id: string, code: string, name: string, description: string, names: Array<{ locale: string, value: string }>, descriptions: Array<{ locale: string, value: string }> } }> } };

export type ConsoleCreateClientMutationVariables = Exact<{
  input: CreateClientInput;
}>;


export type ConsoleCreateClientMutation = { createClient: { clientId: string, version: string } };

export type ConsoleUpdateClientMutationVariables = Exact<{
  input: UpdateClientInput;
}>;


export type ConsoleUpdateClientMutation = { updateClient: { clientId: string, version: string } };

export type ConsoleEnableClientMutationVariables = Exact<{
  input: ClientStateInput;
}>;


export type ConsoleEnableClientMutation = { enableClient: { clientId: string, version: string } };

export type ConsoleDisableClientMutationVariables = Exact<{
  input: ClientStateInput;
}>;


export type ConsoleDisableClientMutation = { disableClient: { clientId: string, version: string } };

export type ConsoleDeleteClientMutationVariables = Exact<{
  input: ClientStateInput;
}>;


export type ConsoleDeleteClientMutation = { deleteClient: { clientId: string, deleted: boolean } };

export type ConsoleCreateClientSecretMutationVariables = Exact<{
  input: CreateClientSecretInput;
}>;


export type ConsoleCreateClientSecretMutation = { createClientSecret: { clientId: string, version: string, secret: string, credential: { id: string, hint: string, expiresAt: string | null } } };

export type ConsoleRotateClientSecretMutationVariables = Exact<{
  input: RotateClientSecretInput;
}>;


export type ConsoleRotateClientSecretMutation = { rotateClientSecret: { clientId: string, version: string, secret: string, credential: { id: string, hint: string, expiresAt: string | null } } };

export type ConsoleAddClientPublicKeyMutationVariables = Exact<{
  input: AddClientPublicKeyInput;
}>;


export type ConsoleAddClientPublicKeyMutation = { addClientPublicKey: { clientId: string, version: string } };

export type ConsoleAddClientJwksUriMutationVariables = Exact<{
  input: AddClientJwksUriInput;
}>;


export type ConsoleAddClientJwksUriMutation = { addClientJwksUri: { clientId: string, version: string } };

export type ConsoleRevokeClientCredentialMutationVariables = Exact<{
  input: RevokeClientCredentialInput;
}>;


export type ConsoleRevokeClientCredentialMutation = { revokeClientCredential: { clientId: string, version: string } };

export type ConsoleSetClientScopesMutationVariables = Exact<{
  input: SetClientScopesInput;
}>;


export type ConsoleSetClientScopesMutation = { setClientScopes: { clientId: string, version: string, scopeIds: Array<string>, clientGrantedScopeIds: Array<string> } };

export type ConsoleClientEndpointsQueryVariables = Exact<{ [key: string]: never; }>;


export type ConsoleClientEndpointsQuery = { instanceMetadata: { issuer: string, openidConfigurationUrl: string, oauthAuthorizationServerMetadataUrl: string, jwksUri: string, authorizationEndpoint: string, tokenEndpoint: string | null, pushedAuthorizationRequestEndpoint: string | null, userinfoEndpoint: string | null, deviceAuthorizationEndpoint: string | null, revocationEndpoint: string, introspectionEndpoint: string, endSessionEndpoint: string | null, checkSessionIframe: string | null, registrationEndpoint: string | null } };

export type ConsoleClientMetadataOptionsQueryVariables = Exact<{ [key: string]: never; }>;


export type ConsoleClientMetadataOptionsQuery = { clientMetadataOptions: { subjectTypes: Array<string>, acrValues: Array<string>, idTokenSigningAlgs: Array<string>, idTokenEncryptionAlgs: Array<string>, idTokenEncryptionEncs: Array<string>, userinfoSigningAlgs: Array<string>, userinfoEncryptionAlgs: Array<string>, userinfoEncryptionEncs: Array<string>, requestObjectSigningAlgs: Array<string>, requestObjectEncryptionAlgs: Array<string>, requestObjectEncryptionEncs: Array<string>, tokenEndpointAuthSigningAlgs: Array<string>, activeSigningAlgs: Array<string>, activeRequestObjectEncryptionAlgs: Array<string> } };

export type ConsoleResourcesQueryVariables = Exact<{
  filter?: ResourceFilter | null | undefined;
  orderBy?: ResourceOrder | null | undefined;
  first?: number | null | undefined;
  after?: string | null | undefined;
  last?: number | null | undefined;
  before?: string | null | undefined;
}>;


export type ConsoleResourcesQuery = { resources: { pageInfo: { hasNextPage: boolean, hasPreviousPage: boolean, startCursor: string | null, endCursor: string | null }, edges: Array<{ cursor: string, node: { id: string, name: string, uri: string, enabled: boolean, createdAt: string, updatedAt: string | null } }> } };

export type ConsoleResourceQueryVariables = Exact<{
  id: string | number;
}>;


export type ConsoleResourceQuery = { resource: { id: string, name: string, uri: string, enabled: boolean, version: string, createdAt: string, updatedAt: string | null } | null };

export type ConsolePermissionRolesQueryVariables = Exact<{
  id: string | number;
  first?: number | null | undefined;
  after?: string | null | undefined;
  last?: number | null | undefined;
  before?: string | null | undefined;
}>;


export type ConsolePermissionRolesQuery = { permission: { id: string, roles: { pageInfo: { hasNextPage: boolean, hasPreviousPage: boolean, startCursor: string | null, endCursor: string | null }, edges: Array<{ node: { id: string, name: string, builtIn: boolean, enabled: boolean, description: string, names: Array<{ locale: string, value: string }> } }> } } | null };

export type ConsolePermissionQueryVariables = Exact<{
  id: string | number;
  includeResource: boolean;
}>;


export type ConsolePermissionQuery = { permission: { id: string, resourceId: string | null, code: string, name: string, description: string, builtIn: boolean, enabled: boolean, version: string, createdAt: string, updatedAt: string | null, names: Array<{ locale: string, value: string }>, descriptions: Array<{ locale: string, value: string }>, resource?: { id: string, uri: string, name: string, enabled: boolean } | null } | null };

export type ConsoleCreatePermissionMutationVariables = Exact<{
  input: CreateScopeInput;
}>;


export type ConsoleCreatePermissionMutation = { createPermission: { version: string, permissionId: string } };

export type ConsoleUpdatePermissionMutationVariables = Exact<{
  input: UpdateScopeInput;
}>;


export type ConsoleUpdatePermissionMutation = { updatePermission: { version: string, permissionId: string } };

export type ConsoleEnablePermissionMutationVariables = Exact<{
  input: ScopeStateInput;
}>;


export type ConsoleEnablePermissionMutation = { enablePermission: { version: string, permissionId: string } };

export type ConsoleDisablePermissionMutationVariables = Exact<{
  input: ScopeStateInput;
}>;


export type ConsoleDisablePermissionMutation = { disablePermission: { version: string, permissionId: string } };

export type ConsoleScopesQueryVariables = Exact<{
  filter?: ScopeFilter | null | undefined;
  first?: number | null | undefined;
  after?: string | null | undefined;
  last?: number | null | undefined;
  before?: string | null | undefined;
}>;


export type ConsoleScopesQuery = { scopes: { pageInfo: { hasNextPage: boolean, hasPreviousPage: boolean, startCursor: string | null, endCursor: string | null }, edges: Array<{ cursor: string, node: { id: string, code: string, name: string, description: string, names: Array<{ locale: string, value: string }> } }> } };

export type ConsolePermissionsQueryVariables = Exact<{
  filter?: ScopeFilter | null | undefined;
  orderBy?: ScopeOrder | null | undefined;
  first?: number | null | undefined;
  after?: string | null | undefined;
  last?: number | null | undefined;
  before?: string | null | undefined;
  includeResource: boolean;
}>;


export type ConsolePermissionsQuery = { permissions: { totalCount: number, pageInfo: { hasNextPage: boolean, hasPreviousPage: boolean, startCursor: string | null, endCursor: string | null }, edges: Array<{ cursor: string, node: { id: string, resourceId: string | null, code: string, name: string, description: string, builtIn: boolean, enabled: boolean, version: string, createdAt: string, updatedAt: string | null, names: Array<{ locale: string, value: string }>, descriptions: Array<{ locale: string, value: string }>, resource?: { id: string, uri: string, name: string, enabled: boolean } | null } }> } };

export type ConsoleResourcePermissionsQueryVariables = Exact<{
  filter?: ScopeFilter | null | undefined;
  orderBy?: ScopeOrder | null | undefined;
  first?: number | null | undefined;
  after?: string | null | undefined;
  last?: number | null | undefined;
  before?: string | null | undefined;
}>;


export type ConsoleResourcePermissionsQuery = { permissions: { totalCount: number, pageInfo: { hasNextPage: boolean, hasPreviousPage: boolean, startCursor: string | null, endCursor: string | null }, edges: Array<{ cursor: string, node: { id: string, code: string, name: string, description: string, builtIn: boolean, enabled: boolean, createdAt: string, names: Array<{ locale: string, value: string }>, descriptions: Array<{ locale: string, value: string }> } }> } };

export type InstanceDashboardQueryVariables = Exact<{
  timeZone: string;
  includeUsers: boolean;
  includeClients: boolean;
  includeSessions: boolean;
  includeResources: boolean;
}>;


export type InstanceDashboardQuery = { instanceOverview: { generatedAt: string, users?: { total: number, enabled: number, createdLast7Days: number, registrations: Array<{ date: string, count: number }> } | null, clients?: { total: number, enabled: number, builtIn: number } | null, sessions?: { active: number, createdLast24Hours: number } | null, resources?: { total: number, enabled: number } | null } };

export type AuditEventFieldsFragment = { id: string, occurredAt: string, category: AuditCategory, action: AuditAction, outcome: AuditOutcome, failureReason: AuditFailureReason | null, clientId: string | null, authMethods: Array<AuditAuthMethod>, ipAddress: string | null, userAgent: string | null, requestId: string | null, traceId: string | null, actor: { kind: AuditActorKind, id: string | null, oid: string | null, label: string | null, user?: { id: string, username: string, email: string, nickname: string | null } | null, client?: { id: string, name: string, names: Array<{ locale: string, value: string }> } | null }, target: { kind: AuditTargetKind, id: string | null, oid: string, label: string | null } | null, changes: Array<{ field: AuditField, kind: AuditChangeKind, oldValue: unknown, newValue: unknown, added: Array<unknown>, removed: Array<unknown> }> };

export type AuditEventsQueryQueryVariables = Exact<{
  query?: string | null | undefined;
  timeZone?: string | null | undefined;
  orderBy?: AuditEventOrder | null | undefined;
  first?: number | null | undefined;
  after?: string | null | undefined;
  last?: number | null | undefined;
  before?: string | null | undefined;
  includeActorUser: boolean;
  includeActorClient: boolean;
}>;


export type AuditEventsQueryQuery = { auditEvents: { totalCount: number, pageInfo: { hasPreviousPage: boolean, hasNextPage: boolean, startCursor: string | null, endCursor: string | null }, edges: Array<{ cursor: string, node: { id: string, occurredAt: string, category: AuditCategory, action: AuditAction, outcome: AuditOutcome, failureReason: AuditFailureReason | null, clientId: string | null, authMethods: Array<AuditAuthMethod>, ipAddress: string | null, userAgent: string | null, requestId: string | null, traceId: string | null, actor: { kind: AuditActorKind, id: string | null, oid: string | null, label: string | null, user?: { id: string, username: string, email: string, nickname: string | null } | null, client?: { id: string, name: string, names: Array<{ locale: string, value: string }> } | null }, target: { kind: AuditTargetKind, id: string | null, oid: string, label: string | null } | null, changes: Array<{ field: AuditField, kind: AuditChangeKind, oldValue: unknown, newValue: unknown, added: Array<unknown>, removed: Array<unknown> }> } }> } };

export type AuditEventDetailQueryQueryVariables = Exact<{
  id: string | number;
  includeActorUser: boolean;
  includeActorClient: boolean;
}>;


export type AuditEventDetailQueryQuery = { auditEvent: { id: string, occurredAt: string, category: AuditCategory, action: AuditAction, outcome: AuditOutcome, failureReason: AuditFailureReason | null, clientId: string | null, authMethods: Array<AuditAuthMethod>, ipAddress: string | null, userAgent: string | null, requestId: string | null, traceId: string | null, client?: { id: string, name: string, names: Array<{ locale: string, value: string }> } | null, device: { browser: string | null, browserVersion: string | null, os: string | null, osVersion: string | null } | null, actor: { kind: AuditActorKind, id: string | null, oid: string | null, label: string | null, user?: { id: string, username: string, email: string, nickname: string | null } | null, client?: { id: string, name: string, names: Array<{ locale: string, value: string }> } | null }, target: { kind: AuditTargetKind, id: string | null, oid: string, label: string | null } | null, changes: Array<{ field: AuditField, kind: AuditChangeKind, oldValue: unknown, newValue: unknown, added: Array<unknown>, removed: Array<unknown> }> } | null };

export type ConsoleUpdateEmailDeliverySettingsMutationVariables = Exact<{
  input: UpdateEmailDeliverySettingsInput;
}>;


export type ConsoleUpdateEmailDeliverySettingsMutation = { updateEmailDeliverySettings: { clientMutationId: string | null, settings: { general: { issuer: string | null, loginUrl: string | null, consoleUrl: string | null, initializedAt: string | null }, protocol: { oauthVersion: ClientOAuthVersion, requirePushedAuthorizationRequests: boolean, pushedAuthorizationRequestLifetimeSeconds: number, deviceAuthorizationRequestLifetimeSeconds: number, deviceAuthorizationPollingIntervalSeconds: number, dynamicRegistrationEnabled: boolean, accessTokenLifetimeSeconds: number, idTokenLifetimeSeconds: number, refreshTokenLifetimeDays: number, authorizationCodeLifetimeSeconds: number, version: string, pushedAuthorizationRequestLifetimeRange: { min: number, max: number }, deviceAuthorizationRequestLifetimeRange: { min: number, max: number }, deviceAuthorizationPollingIntervalRange: { min: number, max: number }, accessTokenLifetimeRange: { min: number, max: number }, idTokenLifetimeRange: { min: number, max: number }, refreshTokenLifetimeDaysRange: { min: number, max: number }, authorizationCodeLifetimeRange: { min: number, max: number } }, authentication: { breachedPasswordCheckEnabled: boolean, identifierEnumerationAllowed: boolean, emailSignInEnabled: boolean, passwordResetEnabled: boolean, registrationEnabled: boolean, passwordMaxAgeDays: number, passwordHistoryCount: number, passwordMinLength: number, maxFailedAttempts: number, lockoutDurationMinutes: number, version: string, passwordMaxAgeDaysRange: { min: number, max: number }, passwordHistoryCountRange: { min: number, max: number }, passwordMinLengthRange: { min: number, max: number }, maxFailedAttemptsRange: { min: number, max: number }, lockoutDurationMinutesRange: { min: number, max: number }, passwordHashing: { timeCost: number, memoryCostKib: number, parallelism: number, timeCostRange: { min: number, max: number }, memoryCostKibRange: { min: number, max: number }, parallelismRange: { min: number, max: number } } }, session: { sessionLifetimeHours: number, elevatedAuthenticationLifetimeMinutes: number, recentAuthenticationLifetimeMinutes: number, loginLifetimeMinutes: number, version: string, sessionLifetimeHoursRange: { min: number, max: number }, elevatedAuthenticationLifetimeMinutesRange: { min: number, max: number }, recentAuthenticationLifetimeMinutesRange: { min: number, max: number }, loginLifetimeMinutesRange: { min: number, max: number } }, email: { delivery: { enabled: boolean, host: string, port: number, security: SmtpSecurity, senderAddress: string, senderName: string | null, configured: boolean, version: string, portRange: { min: number, max: number }, authentication: { method: EmailAuthenticationMethod, username: string | null, passwordSet: boolean, tokenEndpoint: string | null, clientId: string | null, clientSecretSet: boolean, grant: Xoauth2Grant | null, refreshTokenSet: boolean, scope: string | null } }, policy: { signInCodeLifetimeMinutes: number, passwordResetLifetimeMinutes: number, registrationLifetimeMinutes: number, emailVerificationLifetimeHours: number, userInvitationLifetimeDays: number, resendIntervalSeconds: number, loginMaxSends: number, verificationMaxSends: number, verificationSendWindowHours: number, version: string, signInCodeLifetimeMinutesRange: { min: number, max: number }, passwordResetLifetimeMinutesRange: { min: number, max: number }, registrationLifetimeMinutesRange: { min: number, max: number }, emailVerificationLifetimeHoursRange: { min: number, max: number }, userInvitationLifetimeDaysRange: { min: number, max: number }, resendIntervalSecondsRange: { min: number, max: number }, loginMaxSendsRange: { min: number, max: number }, verificationMaxSendsRange: { min: number, max: number }, verificationSendWindowHoursRange: { min: number, max: number } }, templates: Array<{ kind: EmailTemplateKind, variables: Array<string>, previewScenarios: Array<EmailTemplatePreviewScenario>, customized: boolean, version: string, content: { default: { subject: string, html: string }, translations: Array<{ locale: string, content: { subject: string, html: string } }> }, builtIn: { default: { subject: string, html: string }, translations: Array<{ locale: string, content: { subject: string, html: string } }> } }> } } | null } };

export type ConsoleUpdateEmailPolicySettingsMutationVariables = Exact<{
  input: UpdateEmailPolicySettingsInput;
}>;


export type ConsoleUpdateEmailPolicySettingsMutation = { updateEmailPolicySettings: { clientMutationId: string | null, settings: { general: { issuer: string | null, loginUrl: string | null, consoleUrl: string | null, initializedAt: string | null }, protocol: { oauthVersion: ClientOAuthVersion, requirePushedAuthorizationRequests: boolean, pushedAuthorizationRequestLifetimeSeconds: number, deviceAuthorizationRequestLifetimeSeconds: number, deviceAuthorizationPollingIntervalSeconds: number, dynamicRegistrationEnabled: boolean, accessTokenLifetimeSeconds: number, idTokenLifetimeSeconds: number, refreshTokenLifetimeDays: number, authorizationCodeLifetimeSeconds: number, version: string, pushedAuthorizationRequestLifetimeRange: { min: number, max: number }, deviceAuthorizationRequestLifetimeRange: { min: number, max: number }, deviceAuthorizationPollingIntervalRange: { min: number, max: number }, accessTokenLifetimeRange: { min: number, max: number }, idTokenLifetimeRange: { min: number, max: number }, refreshTokenLifetimeDaysRange: { min: number, max: number }, authorizationCodeLifetimeRange: { min: number, max: number } }, authentication: { breachedPasswordCheckEnabled: boolean, identifierEnumerationAllowed: boolean, emailSignInEnabled: boolean, passwordResetEnabled: boolean, registrationEnabled: boolean, passwordMaxAgeDays: number, passwordHistoryCount: number, passwordMinLength: number, maxFailedAttempts: number, lockoutDurationMinutes: number, version: string, passwordMaxAgeDaysRange: { min: number, max: number }, passwordHistoryCountRange: { min: number, max: number }, passwordMinLengthRange: { min: number, max: number }, maxFailedAttemptsRange: { min: number, max: number }, lockoutDurationMinutesRange: { min: number, max: number }, passwordHashing: { timeCost: number, memoryCostKib: number, parallelism: number, timeCostRange: { min: number, max: number }, memoryCostKibRange: { min: number, max: number }, parallelismRange: { min: number, max: number } } }, session: { sessionLifetimeHours: number, elevatedAuthenticationLifetimeMinutes: number, recentAuthenticationLifetimeMinutes: number, loginLifetimeMinutes: number, version: string, sessionLifetimeHoursRange: { min: number, max: number }, elevatedAuthenticationLifetimeMinutesRange: { min: number, max: number }, recentAuthenticationLifetimeMinutesRange: { min: number, max: number }, loginLifetimeMinutesRange: { min: number, max: number } }, email: { delivery: { enabled: boolean, host: string, port: number, security: SmtpSecurity, senderAddress: string, senderName: string | null, configured: boolean, version: string, portRange: { min: number, max: number }, authentication: { method: EmailAuthenticationMethod, username: string | null, passwordSet: boolean, tokenEndpoint: string | null, clientId: string | null, clientSecretSet: boolean, grant: Xoauth2Grant | null, refreshTokenSet: boolean, scope: string | null } }, policy: { signInCodeLifetimeMinutes: number, passwordResetLifetimeMinutes: number, registrationLifetimeMinutes: number, emailVerificationLifetimeHours: number, userInvitationLifetimeDays: number, resendIntervalSeconds: number, loginMaxSends: number, verificationMaxSends: number, verificationSendWindowHours: number, version: string, signInCodeLifetimeMinutesRange: { min: number, max: number }, passwordResetLifetimeMinutesRange: { min: number, max: number }, registrationLifetimeMinutesRange: { min: number, max: number }, emailVerificationLifetimeHoursRange: { min: number, max: number }, userInvitationLifetimeDaysRange: { min: number, max: number }, resendIntervalSecondsRange: { min: number, max: number }, loginMaxSendsRange: { min: number, max: number }, verificationMaxSendsRange: { min: number, max: number }, verificationSendWindowHoursRange: { min: number, max: number } }, templates: Array<{ kind: EmailTemplateKind, variables: Array<string>, previewScenarios: Array<EmailTemplatePreviewScenario>, customized: boolean, version: string, content: { default: { subject: string, html: string }, translations: Array<{ locale: string, content: { subject: string, html: string } }> }, builtIn: { default: { subject: string, html: string }, translations: Array<{ locale: string, content: { subject: string, html: string } }> } }> } } | null } };

export type ConsoleUpdateEmailTemplateMutationVariables = Exact<{
  input: UpdateEmailTemplateInput;
}>;


export type ConsoleUpdateEmailTemplateMutation = { updateEmailTemplate: { clientMutationId: string | null, settings: { general: { issuer: string | null, loginUrl: string | null, consoleUrl: string | null, initializedAt: string | null }, protocol: { oauthVersion: ClientOAuthVersion, requirePushedAuthorizationRequests: boolean, pushedAuthorizationRequestLifetimeSeconds: number, deviceAuthorizationRequestLifetimeSeconds: number, deviceAuthorizationPollingIntervalSeconds: number, dynamicRegistrationEnabled: boolean, accessTokenLifetimeSeconds: number, idTokenLifetimeSeconds: number, refreshTokenLifetimeDays: number, authorizationCodeLifetimeSeconds: number, version: string, pushedAuthorizationRequestLifetimeRange: { min: number, max: number }, deviceAuthorizationRequestLifetimeRange: { min: number, max: number }, deviceAuthorizationPollingIntervalRange: { min: number, max: number }, accessTokenLifetimeRange: { min: number, max: number }, idTokenLifetimeRange: { min: number, max: number }, refreshTokenLifetimeDaysRange: { min: number, max: number }, authorizationCodeLifetimeRange: { min: number, max: number } }, authentication: { breachedPasswordCheckEnabled: boolean, identifierEnumerationAllowed: boolean, emailSignInEnabled: boolean, passwordResetEnabled: boolean, registrationEnabled: boolean, passwordMaxAgeDays: number, passwordHistoryCount: number, passwordMinLength: number, maxFailedAttempts: number, lockoutDurationMinutes: number, version: string, passwordMaxAgeDaysRange: { min: number, max: number }, passwordHistoryCountRange: { min: number, max: number }, passwordMinLengthRange: { min: number, max: number }, maxFailedAttemptsRange: { min: number, max: number }, lockoutDurationMinutesRange: { min: number, max: number }, passwordHashing: { timeCost: number, memoryCostKib: number, parallelism: number, timeCostRange: { min: number, max: number }, memoryCostKibRange: { min: number, max: number }, parallelismRange: { min: number, max: number } } }, session: { sessionLifetimeHours: number, elevatedAuthenticationLifetimeMinutes: number, recentAuthenticationLifetimeMinutes: number, loginLifetimeMinutes: number, version: string, sessionLifetimeHoursRange: { min: number, max: number }, elevatedAuthenticationLifetimeMinutesRange: { min: number, max: number }, recentAuthenticationLifetimeMinutesRange: { min: number, max: number }, loginLifetimeMinutesRange: { min: number, max: number } }, email: { delivery: { enabled: boolean, host: string, port: number, security: SmtpSecurity, senderAddress: string, senderName: string | null, configured: boolean, version: string, portRange: { min: number, max: number }, authentication: { method: EmailAuthenticationMethod, username: string | null, passwordSet: boolean, tokenEndpoint: string | null, clientId: string | null, clientSecretSet: boolean, grant: Xoauth2Grant | null, refreshTokenSet: boolean, scope: string | null } }, policy: { signInCodeLifetimeMinutes: number, passwordResetLifetimeMinutes: number, registrationLifetimeMinutes: number, emailVerificationLifetimeHours: number, userInvitationLifetimeDays: number, resendIntervalSeconds: number, loginMaxSends: number, verificationMaxSends: number, verificationSendWindowHours: number, version: string, signInCodeLifetimeMinutesRange: { min: number, max: number }, passwordResetLifetimeMinutesRange: { min: number, max: number }, registrationLifetimeMinutesRange: { min: number, max: number }, emailVerificationLifetimeHoursRange: { min: number, max: number }, userInvitationLifetimeDaysRange: { min: number, max: number }, resendIntervalSecondsRange: { min: number, max: number }, loginMaxSendsRange: { min: number, max: number }, verificationMaxSendsRange: { min: number, max: number }, verificationSendWindowHoursRange: { min: number, max: number } }, templates: Array<{ kind: EmailTemplateKind, variables: Array<string>, previewScenarios: Array<EmailTemplatePreviewScenario>, customized: boolean, version: string, content: { default: { subject: string, html: string }, translations: Array<{ locale: string, content: { subject: string, html: string } }> }, builtIn: { default: { subject: string, html: string }, translations: Array<{ locale: string, content: { subject: string, html: string } }> } }> } } | null } };

export type ConsoleSendTestEmailMutationVariables = Exact<{
  input: SendTestEmailInput;
}>;


export type ConsoleSendTestEmailMutation = { sendTestEmail: { sent: boolean, clientMutationId: string | null } };

export type ConsoleEmailTemplatePreviewQueryVariables = Exact<{
  input: EmailTemplatePreviewInput;
}>;


export type ConsoleEmailTemplatePreviewQuery = { emailTemplatePreview: { subject: string, html: string } | null };

export type ConsoleKeyFieldsFragment = { id: string, keyId: string, use: KeyUse, status: KeyStatus, inUse: boolean, algorithms: Array<string>, keyIds: Array<string>, hasCertificate: boolean, rotatedFromId: string | null, createdAt: string, expiresAt: string | null, rotatedAt: string | null, revokedAt: string | null };

export type ConsoleKeysQueryVariables = Exact<{
  filter?: KeyFilter | null | undefined;
  first?: number | null | undefined;
  after?: string | null | undefined;
  last?: number | null | undefined;
  before?: string | null | undefined;
}>;


export type ConsoleKeysQuery = { keys: { totalCount: number, pageInfo: { hasNextPage: boolean, hasPreviousPage: boolean, startCursor: string | null, endCursor: string | null }, edges: Array<{ cursor: string, node: { id: string, keyId: string, use: KeyUse, status: KeyStatus, inUse: boolean, algorithms: Array<string>, keyIds: Array<string>, hasCertificate: boolean, rotatedFromId: string | null, createdAt: string, expiresAt: string | null, rotatedAt: string | null, revokedAt: string | null } }> } };

export type ConsoleRotateKeyMutationVariables = Exact<{
  input: KeyLifecycleInput;
}>;


export type ConsoleRotateKeyMutation = { rotateKey: { clientMutationId: string | null, key: { id: string, keyId: string, use: KeyUse, status: KeyStatus, inUse: boolean, algorithms: Array<string>, keyIds: Array<string>, hasCertificate: boolean, rotatedFromId: string | null, createdAt: string, expiresAt: string | null, rotatedAt: string | null, revokedAt: string | null } | null, successor: { id: string, keyId: string, use: KeyUse, status: KeyStatus, inUse: boolean, algorithms: Array<string>, keyIds: Array<string>, hasCertificate: boolean, rotatedFromId: string | null, createdAt: string, expiresAt: string | null, rotatedAt: string | null, revokedAt: string | null } | null } };

export type ConsoleRevokeKeyMutationVariables = Exact<{
  input: KeyLifecycleInput;
}>;


export type ConsoleRevokeKeyMutation = { revokeKey: { clientMutationId: string | null, key: { id: string, keyId: string, use: KeyUse, status: KeyStatus, inUse: boolean, algorithms: Array<string>, keyIds: Array<string>, hasCertificate: boolean, rotatedFromId: string | null, createdAt: string, expiresAt: string | null, rotatedAt: string | null, revokedAt: string | null } | null } };

export type ConsoleRotateAndRevokeKeyMutationVariables = Exact<{
  input: KeyLifecycleInput;
}>;


export type ConsoleRotateAndRevokeKeyMutation = { rotateAndRevokeKey: { clientMutationId: string | null, key: { id: string, keyId: string, use: KeyUse, status: KeyStatus, inUse: boolean, algorithms: Array<string>, keyIds: Array<string>, hasCertificate: boolean, rotatedFromId: string | null, createdAt: string, expiresAt: string | null, rotatedAt: string | null, revokedAt: string | null } | null, successor: { id: string, keyId: string, use: KeyUse, status: KeyStatus, inUse: boolean, algorithms: Array<string>, keyIds: Array<string>, hasCertificate: boolean, rotatedFromId: string | null, createdAt: string, expiresAt: string | null, rotatedAt: string | null, revokedAt: string | null } | null } };

export type ConsoleJwksUriQueryVariables = Exact<{ [key: string]: never; }>;


export type ConsoleJwksUriQuery = { instanceMetadata: { jwksUri: string } };

export type ConsoleCreateSigningKeyMutationVariables = Exact<{
  input: CreateSigningKeyInput;
}>;


export type ConsoleCreateSigningKeyMutation = { createSigningKey: { clientMutationId: string | null, key: { id: string, keyId: string, use: KeyUse, status: KeyStatus, inUse: boolean, algorithms: Array<string>, keyIds: Array<string>, hasCertificate: boolean, rotatedFromId: string | null, createdAt: string, expiresAt: string | null, rotatedAt: string | null, revokedAt: string | null } | null } };

export type ConsoleSigningKeyAlgorithmsQueryVariables = Exact<{ [key: string]: never; }>;


export type ConsoleSigningKeyAlgorithmsQuery = { signingKeyAlgorithms: Array<{ algorithm: SigningAlgorithm, keyAlgorithm: KeyAlgorithm, keyName: string }> };

export type ConsoleInstanceSettingsFieldsFragment = { general: { issuer: string | null, loginUrl: string | null, consoleUrl: string | null, initializedAt: string | null }, protocol: { oauthVersion: ClientOAuthVersion, requirePushedAuthorizationRequests: boolean, pushedAuthorizationRequestLifetimeSeconds: number, deviceAuthorizationRequestLifetimeSeconds: number, deviceAuthorizationPollingIntervalSeconds: number, dynamicRegistrationEnabled: boolean, accessTokenLifetimeSeconds: number, idTokenLifetimeSeconds: number, refreshTokenLifetimeDays: number, authorizationCodeLifetimeSeconds: number, version: string, pushedAuthorizationRequestLifetimeRange: { min: number, max: number }, deviceAuthorizationRequestLifetimeRange: { min: number, max: number }, deviceAuthorizationPollingIntervalRange: { min: number, max: number }, accessTokenLifetimeRange: { min: number, max: number }, idTokenLifetimeRange: { min: number, max: number }, refreshTokenLifetimeDaysRange: { min: number, max: number }, authorizationCodeLifetimeRange: { min: number, max: number } }, authentication: { breachedPasswordCheckEnabled: boolean, identifierEnumerationAllowed: boolean, emailSignInEnabled: boolean, passwordResetEnabled: boolean, registrationEnabled: boolean, passwordMaxAgeDays: number, passwordHistoryCount: number, passwordMinLength: number, maxFailedAttempts: number, lockoutDurationMinutes: number, version: string, passwordMaxAgeDaysRange: { min: number, max: number }, passwordHistoryCountRange: { min: number, max: number }, passwordMinLengthRange: { min: number, max: number }, maxFailedAttemptsRange: { min: number, max: number }, lockoutDurationMinutesRange: { min: number, max: number }, passwordHashing: { timeCost: number, memoryCostKib: number, parallelism: number, timeCostRange: { min: number, max: number }, memoryCostKibRange: { min: number, max: number }, parallelismRange: { min: number, max: number } } }, session: { sessionLifetimeHours: number, elevatedAuthenticationLifetimeMinutes: number, recentAuthenticationLifetimeMinutes: number, loginLifetimeMinutes: number, version: string, sessionLifetimeHoursRange: { min: number, max: number }, elevatedAuthenticationLifetimeMinutesRange: { min: number, max: number }, recentAuthenticationLifetimeMinutesRange: { min: number, max: number }, loginLifetimeMinutesRange: { min: number, max: number } }, email: { delivery: { enabled: boolean, host: string, port: number, security: SmtpSecurity, senderAddress: string, senderName: string | null, configured: boolean, version: string, portRange: { min: number, max: number }, authentication: { method: EmailAuthenticationMethod, username: string | null, passwordSet: boolean, tokenEndpoint: string | null, clientId: string | null, clientSecretSet: boolean, grant: Xoauth2Grant | null, refreshTokenSet: boolean, scope: string | null } }, policy: { signInCodeLifetimeMinutes: number, passwordResetLifetimeMinutes: number, registrationLifetimeMinutes: number, emailVerificationLifetimeHours: number, userInvitationLifetimeDays: number, resendIntervalSeconds: number, loginMaxSends: number, verificationMaxSends: number, verificationSendWindowHours: number, version: string, signInCodeLifetimeMinutesRange: { min: number, max: number }, passwordResetLifetimeMinutesRange: { min: number, max: number }, registrationLifetimeMinutesRange: { min: number, max: number }, emailVerificationLifetimeHoursRange: { min: number, max: number }, userInvitationLifetimeDaysRange: { min: number, max: number }, resendIntervalSecondsRange: { min: number, max: number }, loginMaxSendsRange: { min: number, max: number }, verificationMaxSendsRange: { min: number, max: number }, verificationSendWindowHoursRange: { min: number, max: number } }, templates: Array<{ kind: EmailTemplateKind, variables: Array<string>, previewScenarios: Array<EmailTemplatePreviewScenario>, customized: boolean, version: string, content: { default: { subject: string, html: string }, translations: Array<{ locale: string, content: { subject: string, html: string } }> }, builtIn: { default: { subject: string, html: string }, translations: Array<{ locale: string, content: { subject: string, html: string } }> } }> } };

export type ConsoleLocalizedEmailTemplateFieldsFragment = { default: { subject: string, html: string }, translations: Array<{ locale: string, content: { subject: string, html: string } }> };

export type ConsoleInstanceSettingsQueryVariables = Exact<{ [key: string]: never; }>;


export type ConsoleInstanceSettingsQuery = { instanceSettings: { general: { issuer: string | null, loginUrl: string | null, consoleUrl: string | null, initializedAt: string | null }, protocol: { oauthVersion: ClientOAuthVersion, requirePushedAuthorizationRequests: boolean, pushedAuthorizationRequestLifetimeSeconds: number, deviceAuthorizationRequestLifetimeSeconds: number, deviceAuthorizationPollingIntervalSeconds: number, dynamicRegistrationEnabled: boolean, accessTokenLifetimeSeconds: number, idTokenLifetimeSeconds: number, refreshTokenLifetimeDays: number, authorizationCodeLifetimeSeconds: number, version: string, pushedAuthorizationRequestLifetimeRange: { min: number, max: number }, deviceAuthorizationRequestLifetimeRange: { min: number, max: number }, deviceAuthorizationPollingIntervalRange: { min: number, max: number }, accessTokenLifetimeRange: { min: number, max: number }, idTokenLifetimeRange: { min: number, max: number }, refreshTokenLifetimeDaysRange: { min: number, max: number }, authorizationCodeLifetimeRange: { min: number, max: number } }, authentication: { breachedPasswordCheckEnabled: boolean, identifierEnumerationAllowed: boolean, emailSignInEnabled: boolean, passwordResetEnabled: boolean, registrationEnabled: boolean, passwordMaxAgeDays: number, passwordHistoryCount: number, passwordMinLength: number, maxFailedAttempts: number, lockoutDurationMinutes: number, version: string, passwordMaxAgeDaysRange: { min: number, max: number }, passwordHistoryCountRange: { min: number, max: number }, passwordMinLengthRange: { min: number, max: number }, maxFailedAttemptsRange: { min: number, max: number }, lockoutDurationMinutesRange: { min: number, max: number }, passwordHashing: { timeCost: number, memoryCostKib: number, parallelism: number, timeCostRange: { min: number, max: number }, memoryCostKibRange: { min: number, max: number }, parallelismRange: { min: number, max: number } } }, session: { sessionLifetimeHours: number, elevatedAuthenticationLifetimeMinutes: number, recentAuthenticationLifetimeMinutes: number, loginLifetimeMinutes: number, version: string, sessionLifetimeHoursRange: { min: number, max: number }, elevatedAuthenticationLifetimeMinutesRange: { min: number, max: number }, recentAuthenticationLifetimeMinutesRange: { min: number, max: number }, loginLifetimeMinutesRange: { min: number, max: number } }, email: { delivery: { enabled: boolean, host: string, port: number, security: SmtpSecurity, senderAddress: string, senderName: string | null, configured: boolean, version: string, portRange: { min: number, max: number }, authentication: { method: EmailAuthenticationMethod, username: string | null, passwordSet: boolean, tokenEndpoint: string | null, clientId: string | null, clientSecretSet: boolean, grant: Xoauth2Grant | null, refreshTokenSet: boolean, scope: string | null } }, policy: { signInCodeLifetimeMinutes: number, passwordResetLifetimeMinutes: number, registrationLifetimeMinutes: number, emailVerificationLifetimeHours: number, userInvitationLifetimeDays: number, resendIntervalSeconds: number, loginMaxSends: number, verificationMaxSends: number, verificationSendWindowHours: number, version: string, signInCodeLifetimeMinutesRange: { min: number, max: number }, passwordResetLifetimeMinutesRange: { min: number, max: number }, registrationLifetimeMinutesRange: { min: number, max: number }, emailVerificationLifetimeHoursRange: { min: number, max: number }, userInvitationLifetimeDaysRange: { min: number, max: number }, resendIntervalSecondsRange: { min: number, max: number }, loginMaxSendsRange: { min: number, max: number }, verificationMaxSendsRange: { min: number, max: number }, verificationSendWindowHoursRange: { min: number, max: number } }, templates: Array<{ kind: EmailTemplateKind, variables: Array<string>, previewScenarios: Array<EmailTemplatePreviewScenario>, customized: boolean, version: string, content: { default: { subject: string, html: string }, translations: Array<{ locale: string, content: { subject: string, html: string } }> }, builtIn: { default: { subject: string, html: string }, translations: Array<{ locale: string, content: { subject: string, html: string } }> } }> } } | null };

export type ConsoleUpdateProtocolSettingsMutationVariables = Exact<{
  input: UpdateProtocolSettingsInput;
}>;


export type ConsoleUpdateProtocolSettingsMutation = { updateProtocolSettings: { clientMutationId: string | null, settings: { general: { issuer: string | null, loginUrl: string | null, consoleUrl: string | null, initializedAt: string | null }, protocol: { oauthVersion: ClientOAuthVersion, requirePushedAuthorizationRequests: boolean, pushedAuthorizationRequestLifetimeSeconds: number, deviceAuthorizationRequestLifetimeSeconds: number, deviceAuthorizationPollingIntervalSeconds: number, dynamicRegistrationEnabled: boolean, accessTokenLifetimeSeconds: number, idTokenLifetimeSeconds: number, refreshTokenLifetimeDays: number, authorizationCodeLifetimeSeconds: number, version: string, pushedAuthorizationRequestLifetimeRange: { min: number, max: number }, deviceAuthorizationRequestLifetimeRange: { min: number, max: number }, deviceAuthorizationPollingIntervalRange: { min: number, max: number }, accessTokenLifetimeRange: { min: number, max: number }, idTokenLifetimeRange: { min: number, max: number }, refreshTokenLifetimeDaysRange: { min: number, max: number }, authorizationCodeLifetimeRange: { min: number, max: number } }, authentication: { breachedPasswordCheckEnabled: boolean, identifierEnumerationAllowed: boolean, emailSignInEnabled: boolean, passwordResetEnabled: boolean, registrationEnabled: boolean, passwordMaxAgeDays: number, passwordHistoryCount: number, passwordMinLength: number, maxFailedAttempts: number, lockoutDurationMinutes: number, version: string, passwordMaxAgeDaysRange: { min: number, max: number }, passwordHistoryCountRange: { min: number, max: number }, passwordMinLengthRange: { min: number, max: number }, maxFailedAttemptsRange: { min: number, max: number }, lockoutDurationMinutesRange: { min: number, max: number }, passwordHashing: { timeCost: number, memoryCostKib: number, parallelism: number, timeCostRange: { min: number, max: number }, memoryCostKibRange: { min: number, max: number }, parallelismRange: { min: number, max: number } } }, session: { sessionLifetimeHours: number, elevatedAuthenticationLifetimeMinutes: number, recentAuthenticationLifetimeMinutes: number, loginLifetimeMinutes: number, version: string, sessionLifetimeHoursRange: { min: number, max: number }, elevatedAuthenticationLifetimeMinutesRange: { min: number, max: number }, recentAuthenticationLifetimeMinutesRange: { min: number, max: number }, loginLifetimeMinutesRange: { min: number, max: number } }, email: { delivery: { enabled: boolean, host: string, port: number, security: SmtpSecurity, senderAddress: string, senderName: string | null, configured: boolean, version: string, portRange: { min: number, max: number }, authentication: { method: EmailAuthenticationMethod, username: string | null, passwordSet: boolean, tokenEndpoint: string | null, clientId: string | null, clientSecretSet: boolean, grant: Xoauth2Grant | null, refreshTokenSet: boolean, scope: string | null } }, policy: { signInCodeLifetimeMinutes: number, passwordResetLifetimeMinutes: number, registrationLifetimeMinutes: number, emailVerificationLifetimeHours: number, userInvitationLifetimeDays: number, resendIntervalSeconds: number, loginMaxSends: number, verificationMaxSends: number, verificationSendWindowHours: number, version: string, signInCodeLifetimeMinutesRange: { min: number, max: number }, passwordResetLifetimeMinutesRange: { min: number, max: number }, registrationLifetimeMinutesRange: { min: number, max: number }, emailVerificationLifetimeHoursRange: { min: number, max: number }, userInvitationLifetimeDaysRange: { min: number, max: number }, resendIntervalSecondsRange: { min: number, max: number }, loginMaxSendsRange: { min: number, max: number }, verificationMaxSendsRange: { min: number, max: number }, verificationSendWindowHoursRange: { min: number, max: number } }, templates: Array<{ kind: EmailTemplateKind, variables: Array<string>, previewScenarios: Array<EmailTemplatePreviewScenario>, customized: boolean, version: string, content: { default: { subject: string, html: string }, translations: Array<{ locale: string, content: { subject: string, html: string } }> }, builtIn: { default: { subject: string, html: string }, translations: Array<{ locale: string, content: { subject: string, html: string } }> } }> } } | null } };

export type ConsoleUpdateAuthenticationSettingsMutationVariables = Exact<{
  input: UpdateAuthenticationSettingsInput;
}>;


export type ConsoleUpdateAuthenticationSettingsMutation = { updateAuthenticationSettings: { clientMutationId: string | null, settings: { general: { issuer: string | null, loginUrl: string | null, consoleUrl: string | null, initializedAt: string | null }, protocol: { oauthVersion: ClientOAuthVersion, requirePushedAuthorizationRequests: boolean, pushedAuthorizationRequestLifetimeSeconds: number, deviceAuthorizationRequestLifetimeSeconds: number, deviceAuthorizationPollingIntervalSeconds: number, dynamicRegistrationEnabled: boolean, accessTokenLifetimeSeconds: number, idTokenLifetimeSeconds: number, refreshTokenLifetimeDays: number, authorizationCodeLifetimeSeconds: number, version: string, pushedAuthorizationRequestLifetimeRange: { min: number, max: number }, deviceAuthorizationRequestLifetimeRange: { min: number, max: number }, deviceAuthorizationPollingIntervalRange: { min: number, max: number }, accessTokenLifetimeRange: { min: number, max: number }, idTokenLifetimeRange: { min: number, max: number }, refreshTokenLifetimeDaysRange: { min: number, max: number }, authorizationCodeLifetimeRange: { min: number, max: number } }, authentication: { breachedPasswordCheckEnabled: boolean, identifierEnumerationAllowed: boolean, emailSignInEnabled: boolean, passwordResetEnabled: boolean, registrationEnabled: boolean, passwordMaxAgeDays: number, passwordHistoryCount: number, passwordMinLength: number, maxFailedAttempts: number, lockoutDurationMinutes: number, version: string, passwordMaxAgeDaysRange: { min: number, max: number }, passwordHistoryCountRange: { min: number, max: number }, passwordMinLengthRange: { min: number, max: number }, maxFailedAttemptsRange: { min: number, max: number }, lockoutDurationMinutesRange: { min: number, max: number }, passwordHashing: { timeCost: number, memoryCostKib: number, parallelism: number, timeCostRange: { min: number, max: number }, memoryCostKibRange: { min: number, max: number }, parallelismRange: { min: number, max: number } } }, session: { sessionLifetimeHours: number, elevatedAuthenticationLifetimeMinutes: number, recentAuthenticationLifetimeMinutes: number, loginLifetimeMinutes: number, version: string, sessionLifetimeHoursRange: { min: number, max: number }, elevatedAuthenticationLifetimeMinutesRange: { min: number, max: number }, recentAuthenticationLifetimeMinutesRange: { min: number, max: number }, loginLifetimeMinutesRange: { min: number, max: number } }, email: { delivery: { enabled: boolean, host: string, port: number, security: SmtpSecurity, senderAddress: string, senderName: string | null, configured: boolean, version: string, portRange: { min: number, max: number }, authentication: { method: EmailAuthenticationMethod, username: string | null, passwordSet: boolean, tokenEndpoint: string | null, clientId: string | null, clientSecretSet: boolean, grant: Xoauth2Grant | null, refreshTokenSet: boolean, scope: string | null } }, policy: { signInCodeLifetimeMinutes: number, passwordResetLifetimeMinutes: number, registrationLifetimeMinutes: number, emailVerificationLifetimeHours: number, userInvitationLifetimeDays: number, resendIntervalSeconds: number, loginMaxSends: number, verificationMaxSends: number, verificationSendWindowHours: number, version: string, signInCodeLifetimeMinutesRange: { min: number, max: number }, passwordResetLifetimeMinutesRange: { min: number, max: number }, registrationLifetimeMinutesRange: { min: number, max: number }, emailVerificationLifetimeHoursRange: { min: number, max: number }, userInvitationLifetimeDaysRange: { min: number, max: number }, resendIntervalSecondsRange: { min: number, max: number }, loginMaxSendsRange: { min: number, max: number }, verificationMaxSendsRange: { min: number, max: number }, verificationSendWindowHoursRange: { min: number, max: number } }, templates: Array<{ kind: EmailTemplateKind, variables: Array<string>, previewScenarios: Array<EmailTemplatePreviewScenario>, customized: boolean, version: string, content: { default: { subject: string, html: string }, translations: Array<{ locale: string, content: { subject: string, html: string } }> }, builtIn: { default: { subject: string, html: string }, translations: Array<{ locale: string, content: { subject: string, html: string } }> } }> } } | null } };

export type ConsoleUpdateSessionSettingsMutationVariables = Exact<{
  input: UpdateSessionSettingsInput;
}>;


export type ConsoleUpdateSessionSettingsMutation = { updateSessionSettings: { clientMutationId: string | null, settings: { general: { issuer: string | null, loginUrl: string | null, consoleUrl: string | null, initializedAt: string | null }, protocol: { oauthVersion: ClientOAuthVersion, requirePushedAuthorizationRequests: boolean, pushedAuthorizationRequestLifetimeSeconds: number, deviceAuthorizationRequestLifetimeSeconds: number, deviceAuthorizationPollingIntervalSeconds: number, dynamicRegistrationEnabled: boolean, accessTokenLifetimeSeconds: number, idTokenLifetimeSeconds: number, refreshTokenLifetimeDays: number, authorizationCodeLifetimeSeconds: number, version: string, pushedAuthorizationRequestLifetimeRange: { min: number, max: number }, deviceAuthorizationRequestLifetimeRange: { min: number, max: number }, deviceAuthorizationPollingIntervalRange: { min: number, max: number }, accessTokenLifetimeRange: { min: number, max: number }, idTokenLifetimeRange: { min: number, max: number }, refreshTokenLifetimeDaysRange: { min: number, max: number }, authorizationCodeLifetimeRange: { min: number, max: number } }, authentication: { breachedPasswordCheckEnabled: boolean, identifierEnumerationAllowed: boolean, emailSignInEnabled: boolean, passwordResetEnabled: boolean, registrationEnabled: boolean, passwordMaxAgeDays: number, passwordHistoryCount: number, passwordMinLength: number, maxFailedAttempts: number, lockoutDurationMinutes: number, version: string, passwordMaxAgeDaysRange: { min: number, max: number }, passwordHistoryCountRange: { min: number, max: number }, passwordMinLengthRange: { min: number, max: number }, maxFailedAttemptsRange: { min: number, max: number }, lockoutDurationMinutesRange: { min: number, max: number }, passwordHashing: { timeCost: number, memoryCostKib: number, parallelism: number, timeCostRange: { min: number, max: number }, memoryCostKibRange: { min: number, max: number }, parallelismRange: { min: number, max: number } } }, session: { sessionLifetimeHours: number, elevatedAuthenticationLifetimeMinutes: number, recentAuthenticationLifetimeMinutes: number, loginLifetimeMinutes: number, version: string, sessionLifetimeHoursRange: { min: number, max: number }, elevatedAuthenticationLifetimeMinutesRange: { min: number, max: number }, recentAuthenticationLifetimeMinutesRange: { min: number, max: number }, loginLifetimeMinutesRange: { min: number, max: number } }, email: { delivery: { enabled: boolean, host: string, port: number, security: SmtpSecurity, senderAddress: string, senderName: string | null, configured: boolean, version: string, portRange: { min: number, max: number }, authentication: { method: EmailAuthenticationMethod, username: string | null, passwordSet: boolean, tokenEndpoint: string | null, clientId: string | null, clientSecretSet: boolean, grant: Xoauth2Grant | null, refreshTokenSet: boolean, scope: string | null } }, policy: { signInCodeLifetimeMinutes: number, passwordResetLifetimeMinutes: number, registrationLifetimeMinutes: number, emailVerificationLifetimeHours: number, userInvitationLifetimeDays: number, resendIntervalSeconds: number, loginMaxSends: number, verificationMaxSends: number, verificationSendWindowHours: number, version: string, signInCodeLifetimeMinutesRange: { min: number, max: number }, passwordResetLifetimeMinutesRange: { min: number, max: number }, registrationLifetimeMinutesRange: { min: number, max: number }, emailVerificationLifetimeHoursRange: { min: number, max: number }, userInvitationLifetimeDaysRange: { min: number, max: number }, resendIntervalSecondsRange: { min: number, max: number }, loginMaxSendsRange: { min: number, max: number }, verificationMaxSendsRange: { min: number, max: number }, verificationSendWindowHoursRange: { min: number, max: number } }, templates: Array<{ kind: EmailTemplateKind, variables: Array<string>, previewScenarios: Array<EmailTemplatePreviewScenario>, customized: boolean, version: string, content: { default: { subject: string, html: string }, translations: Array<{ locale: string, content: { subject: string, html: string } }> }, builtIn: { default: { subject: string, html: string }, translations: Array<{ locale: string, content: { subject: string, html: string } }> } }> } } | null } };

export type ConsoleUserRolesQueryVariables = Exact<{
  userId: string | number;
  source?: AuthorizationSource | null | undefined;
  enabled?: boolean | null | undefined;
  orderBy?: UserRoleOrder | null | undefined;
  first?: number | null | undefined;
  after?: string | null | undefined;
  last?: number | null | undefined;
  before?: string | null | undefined;
}>;


export type ConsoleUserRolesQuery = { user: { id: string, roles: { userVersion: string, pageInfo: { hasNextPage: boolean, hasPreviousPage: boolean, startCursor: string | null, endCursor: string | null }, edges: Array<{ cursor: string, source: AuthorizationSource, groupId: string | null, enabled: boolean, revokedAt: string | null, reason: string, createdAt: string, updatedAt: string | null, node: { id: string, name: string, description: string, enabled: boolean, names: Array<{ locale: string, value: string }> } }> } } | null };

export type ConsoleUserRoleVersionQueryVariables = Exact<{
  userId: string | number;
}>;


export type ConsoleUserRoleVersionQuery = { user: { id: string, roles: { userVersion: string } } | null };

export type ConsoleUserPermissionsQueryVariables = Exact<{
  userId: string | number;
  resourceId: string | number;
  source?: AuthorizationSource | null | undefined;
  orderBy?: EffectivePermissionOrder | null | undefined;
  first?: number | null | undefined;
  after?: string | null | undefined;
  last?: number | null | undefined;
  before?: string | null | undefined;
}>;


export type ConsoleUserPermissionsQuery = { user: { id: string, effectivePermissions: { totalCount: number, userVersion: string, pageInfo: { hasNextPage: boolean, hasPreviousPage: boolean, startCursor: string | null, endCursor: string | null }, edges: Array<{ cursor: string, node: { permissionId: string, resourceId: string, code: string, sources: Array<{ roleId: string }>, groupSources: Array<{ groupId: string, roleId: string }> } }> } } | null };

export type ConsoleAssignUserRolesMutationVariables = Exact<{
  input: AssignUserRolesInput;
}>;


export type ConsoleAssignUserRolesMutation = { assignUserRoles: { userId: string, userVersion: string, createdCount: number, revokedCount: number } };

export type ConsoleRevokeUserRolesMutationVariables = Exact<{
  input: RevokeUserRolesInput;
}>;


export type ConsoleRevokeUserRolesMutation = { revokeUserRoles: { userId: string, userVersion: string, createdCount: number, revokedCount: number } };

export type ConsoleAuthorizationLabelsQueryVariables = Exact<{
  ids: Array<string | number> | string | number;
}>;


export type ConsoleAuthorizationLabelsQuery = { nodes: Array<
    | { __typename: 'AuditEvent', id: string }
    | { __typename: 'Client', id: string }
    | { __typename: 'Group', name: string, id: string, names: Array<{ locale: string, value: string }> }
    | { __typename: 'Passkey', id: string }
    | { __typename: 'Resource', id: string }
    | { __typename: 'Role', name: string, description: string, id: string, names: Array<{ locale: string, value: string }> }
    | { __typename: 'Scope', code: string, name: string, description: string, id: string, names: Array<{ locale: string, value: string }>, descriptions: Array<{ locale: string, value: string }> }
    | { __typename: 'Session', id: string }
    | { __typename: 'User', id: string }
  > };

export type ConsoleGroupsQueryVariables = Exact<{
  filter?: GroupFilter | null | undefined;
  orderBy?: GroupOrder | null | undefined;
  first?: number | null | undefined;
  after?: string | null | undefined;
  last?: number | null | undefined;
  before?: string | null | undefined;
}>;


export type ConsoleGroupsQuery = { groups: { totalCount: number, pageInfo: { hasNextPage: boolean, hasPreviousPage: boolean, startCursor: string | null, endCursor: string | null }, edges: Array<{ cursor: string, node: { id: string, builtIn: boolean, name: string, description: string, enabled: boolean, version: string, createdAt: string, updatedAt: string | null, names: Array<{ locale: string, value: string }>, descriptions: Array<{ locale: string, value: string }> } }> } };

export type ConsoleGroupQueryVariables = Exact<{
  id: string | number;
}>;


export type ConsoleGroupQuery = { group: { id: string, builtIn: boolean, name: string, description: string, enabled: boolean, version: string, createdAt: string, updatedAt: string | null, names: Array<{ locale: string, value: string }>, descriptions: Array<{ locale: string, value: string }> } | null };

export type ConsoleGroupMembersQueryVariables = Exact<{
  groupId: string | number;
  filter?: GroupMembershipFilter | null | undefined;
  orderBy?: GroupMembershipOrder | null | undefined;
  first?: number | null | undefined;
  after?: string | null | undefined;
  last?: number | null | undefined;
  before?: string | null | undefined;
}>;


export type ConsoleGroupMembersQuery = { group: { id: string, builtIn: boolean, name: string, description: string, version: string, names: Array<{ locale: string, value: string }>, members: { pageInfo: { hasNextPage: boolean, hasPreviousPage: boolean, startCursor: string | null, endCursor: string | null }, edges: Array<{ cursor: string, enabled: boolean, revokedAt: string | null, createdAt: string, updatedAt: string | null, grantedBy: { id: string, username: string } | null, node: { id: string, username: string, email: string, enabled: boolean | null, locked: boolean | null } }> } } | null };

export type ConsoleGroupRolesQueryVariables = Exact<{
  groupId: string | number;
  filter?: GroupRoleFilter | null | undefined;
  orderBy?: GroupRoleOrder | null | undefined;
  first?: number | null | undefined;
  after?: string | null | undefined;
  last?: number | null | undefined;
  before?: string | null | undefined;
}>;


export type ConsoleGroupRolesQuery = { group: { id: string, builtIn: boolean, name: string, description: string, version: string, names: Array<{ locale: string, value: string }>, roles: { pageInfo: { hasNextPage: boolean, hasPreviousPage: boolean, startCursor: string | null, endCursor: string | null }, edges: Array<{ cursor: string, enabled: boolean, revokedAt: string | null, createdAt: string, updatedAt: string | null, node: { id: string, name: string, builtIn: boolean, description: string, enabled: boolean, version: string, names: Array<{ locale: string, value: string }>, descriptions: Array<{ locale: string, value: string }> } }> } } | null };

export type ConsoleGroupRoleIdsQueryVariables = Exact<{
  groupId: string | number;
  first: number;
  after?: string | null | undefined;
}>;


export type ConsoleGroupRoleIdsQuery = { group: { id: string, version: string, roles: { pageInfo: { hasNextPage: boolean, endCursor: string | null }, edges: Array<{ enabled: boolean, revokedAt: string | null, node: { id: string } }> } } | null };

export type ConsoleCreateGroupMutationVariables = Exact<{
  input: CreateGroupInput;
}>;


export type ConsoleCreateGroupMutation = { createGroup: { groupId: string, version: string } };

export type ConsoleUpdateGroupMutationVariables = Exact<{
  input: UpdateGroupInput;
}>;


export type ConsoleUpdateGroupMutation = { updateGroup: { groupId: string, version: string } };

export type ConsoleAddGroupMemberMutationVariables = Exact<{
  input: AddGroupMemberInput;
}>;


export type ConsoleAddGroupMemberMutation = { addGroupMember: { groupId: string, userId: string, groupVersion: string } };

export type ConsoleRemoveGroupMemberMutationVariables = Exact<{
  input: RemoveGroupMemberInput;
}>;


export type ConsoleRemoveGroupMemberMutation = { removeGroupMember: { groupId: string, userId: string, groupVersion: string } };

export type ConsoleSetGroupRolesMutationVariables = Exact<{
  input: SetGroupRolesInput;
}>;


export type ConsoleSetGroupRolesMutation = { setGroupRoles: { groupId: string, groupVersion: string, roleIds: Array<string>, addedCount: number, removedCount: number } };

export type ConsoleSetGroupEnabledMutationVariables = Exact<{
  input: SetGroupEnabledInput;
}>;


export type ConsoleSetGroupEnabledMutation = { setGroupEnabled: { groupId: string, version: string } };

export type ConsoleDeleteGroupMutationVariables = Exact<{
  input: GroupStateInput;
}>;


export type ConsoleDeleteGroupMutation = { deleteGroup: { groupId: string, deleted: boolean } };

export type ConsolePermissionOptionsQueryVariables = Exact<{
  filter?: ScopeFilter | null | undefined;
  orderBy?: ScopeOrder | null | undefined;
  first?: number | null | undefined;
  after?: string | null | undefined;
  last?: number | null | undefined;
  before?: string | null | undefined;
}>;


export type ConsolePermissionOptionsQuery = { permissions: { totalCount: number, pageInfo: { hasNextPage: boolean, hasPreviousPage: boolean, startCursor: string | null, endCursor: string | null }, edges: Array<{ cursor: string, node: { id: string, resourceId: string | null, code: string, name: string, description: string, builtIn: boolean, enabled: boolean, names: Array<{ locale: string, value: string }>, descriptions: Array<{ locale: string, value: string }> } }> } };

export type ConsoleRoleGroupsQueryVariables = Exact<{
  roleId: string | number;
  filter?: GroupFilter | null | undefined;
  orderBy?: GroupOrder | null | undefined;
  first?: number | null | undefined;
  after?: string | null | undefined;
  last?: number | null | undefined;
  before?: string | null | undefined;
}>;


export type ConsoleRoleGroupsQuery = { role: { id: string, groups: { pageInfo: { hasNextPage: boolean, hasPreviousPage: boolean, startCursor: string | null, endCursor: string | null }, edges: Array<{ cursor: string, node: { id: string, builtIn: boolean, name: string, description: string, enabled: boolean, updatedAt: string | null, names: Array<{ locale: string, value: string }>, descriptions: Array<{ locale: string, value: string }> } }> } } | null };

export type ConsoleRolesQueryVariables = Exact<{
  filter?: RoleFilter | null | undefined;
  orderBy?: RoleOrder | null | undefined;
  first?: number | null | undefined;
  after?: string | null | undefined;
  last?: number | null | undefined;
  before?: string | null | undefined;
}>;


export type ConsoleRolesQuery = { roles: { totalCount: number, pageInfo: { hasNextPage: boolean, hasPreviousPage: boolean, startCursor: string | null, endCursor: string | null }, edges: Array<{ cursor: string, node: { id: string, name: string, description: string, builtIn: boolean, enabled: boolean, version: string, createdAt: string, updatedAt: string | null, names: Array<{ locale: string, value: string }>, descriptions: Array<{ locale: string, value: string }> } }> } };

export type ConsoleRoleQueryVariables = Exact<{
  id: string | number;
}>;


export type ConsoleRoleQuery = { role: { id: string, name: string, description: string, builtIn: boolean, enabled: boolean, version: string, createdAt: string, updatedAt: string | null, names: Array<{ locale: string, value: string }>, descriptions: Array<{ locale: string, value: string }> } | null };

export type ConsoleCreateRoleMutationVariables = Exact<{
  input: CreateRoleInput;
}>;


export type ConsoleCreateRoleMutation = { createRole: { roleId: string, version: string } };

export type ConsoleUpdateRoleMutationVariables = Exact<{
  input: UpdateRoleInput;
}>;


export type ConsoleUpdateRoleMutation = { updateRole: { roleId: string, version: string } };

export type ConsoleEnableRoleMutationVariables = Exact<{
  input: RoleStateInput;
}>;


export type ConsoleEnableRoleMutation = { enableRole: { roleId: string, version: string } };

export type ConsoleDisableRoleMutationVariables = Exact<{
  input: RoleStateInput;
}>;


export type ConsoleDisableRoleMutation = { disableRole: { roleId: string, version: string } };

export type ConsoleSetRolePermissionsMutationVariables = Exact<{
  input: SetRolePermissionsInput;
}>;


export type ConsoleSetRolePermissionsMutation = { setRolePermissions: { roleId: string, version: string } };

export type ConsoleRoleUsersQueryVariables = Exact<{
  roleId: string | number;
  enabled?: boolean | null | undefined;
  orderBy?: UserRoleOrder | null | undefined;
  first?: number | null | undefined;
  after?: string | null | undefined;
  last?: number | null | undefined;
  before?: string | null | undefined;
}>;


export type ConsoleRoleUsersQuery = { role: { id: string, users: { pageInfo: { hasNextPage: boolean, hasPreviousPage: boolean, startCursor: string | null, endCursor: string | null }, edges: Array<{ cursor: string, enabled: boolean, revokedAt: string | null, reason: string, createdAt: string, updatedAt: string | null, node: { id: string, username: string, email: string, enabled: boolean | null, locked: boolean | null, version: string } }> } } | null };

export type ConsoleResourceOptionsQueryVariables = Exact<{
  filter?: ResourceFilter | null | undefined;
  first?: number | null | undefined;
  after?: string | null | undefined;
}>;


export type ConsoleResourceOptionsQuery = { resources: { pageInfo: { hasNextPage: boolean, hasPreviousPage: boolean, startCursor: string | null, endCursor: string | null }, edges: Array<{ cursor: string, node: { id: string, uri: string, name: string, enabled: boolean } }> } };

export type ConsoleUsersQueryVariables = Exact<{
  filter?: UserFilter | null | undefined;
  orderBy?: UserOrder | null | undefined;
  first?: number | null | undefined;
  after?: string | null | undefined;
  last?: number | null | undefined;
  before?: string | null | undefined;
}>;


export type ConsoleUsersQuery = { users: { totalCount: number, pageInfo: { hasNextPage: boolean, hasPreviousPage: boolean, startCursor: string | null, endCursor: string | null }, edges: Array<{ cursor: string, node: { id: string, username: string, email: string, emailVerified: boolean, enabled: boolean | null, locked: boolean | null, lockedUntil: string | null, failedAttempts: number | null, version: string, createdAt: string, updatedAt: string | null, invitation: { expiresAt: string, delivery: { status: EmailDeliveryStatus } } | null } }> } };

export type ConsoleUserQueryVariables = Exact<{
  id: string | number;
}>;


export type ConsoleUserQuery = { user: { id: string, username: string, email: string, emailVerified: boolean, enabled: boolean | null, locked: boolean | null, lockedUntil: string | null, failedAttempts: number | null, requiredActions: Array<UserRequiredAction> | null, version: string, givenName: string | null, familyName: string | null, middleName: string | null, nickname: string | null, profile: string | null, picture: string | null, website: string | null, birthdate: string | null, locale: string | null, theme: string | null, createdAt: string, updatedAt: string | null, invitation: { sentAt: string, expiresAt: string, delivery: { status: EmailDeliveryStatus, failure: EmailDeliveryFailure | null, updatedAt: string } } | null, authenticationMethods: { password: boolean, authenticatorApp: boolean, recoveryCodes: boolean, passkey: boolean } | null } | null };

export type ConsoleUserInvitationsAvailableQueryVariables = Exact<{ [key: string]: never; }>;


export type ConsoleUserInvitationsAvailableQuery = { userInvitationsAvailable: boolean };

export type ConsoleCreateUserMutationVariables = Exact<{
  input: CreateUserInput;
}>;


export type ConsoleCreateUserMutation = { createUser: { userId: string, version: string } };

export type ConsoleSendUserInvitationMutationVariables = Exact<{
  input: SendUserInvitationInput;
}>;


export type ConsoleSendUserInvitationMutation = { sendUserInvitation: { userId: string, invitation: { sentAt: string, expiresAt: string, delivery: { status: EmailDeliveryStatus, failure: EmailDeliveryFailure | null, updatedAt: string } } } };

export type ConsoleUpdateUserMutationVariables = Exact<{
  input: UpdateUserInput;
}>;


export type ConsoleUpdateUserMutation = { updateUser: { userId: string, version: string } };

export type ConsoleEnableUserMutationVariables = Exact<{
  input: UserStateInput;
}>;


export type ConsoleEnableUserMutation = { enableUser: { userId: string, version: string } };

export type ConsoleDisableUserMutationVariables = Exact<{
  input: UserStateInput;
}>;


export type ConsoleDisableUserMutation = { disableUser: { userId: string, version: string } };

export type ConsoleUnlockUserMutationVariables = Exact<{
  input: UnlockUserInput;
}>;


export type ConsoleUnlockUserMutation = { unlockUser: { userId: string, version: string } };

export type ConsoleUserGroupsQueryVariables = Exact<{
  userId: string | number;
  filter?: GroupFilter | null | undefined;
  orderBy?: GroupOrder | null | undefined;
  first?: number | null | undefined;
  after?: string | null | undefined;
  last?: number | null | undefined;
  before?: string | null | undefined;
}>;


export type ConsoleUserGroupsQuery = { user: { id: string, groups: { pageInfo: { hasNextPage: boolean, hasPreviousPage: boolean, startCursor: string | null, endCursor: string | null }, edges: Array<{ cursor: string, node: { id: string, builtIn: boolean, name: string, description: string, enabled: boolean, version: string, names: Array<{ locale: string, value: string }>, descriptions: Array<{ locale: string, value: string }> } }> } } | null };

export type ConsoleUserSessionsQueryVariables = Exact<{
  userId: string | number;
  first?: number | null | undefined;
  after?: string | null | undefined;
  last?: number | null | undefined;
  before?: string | null | undefined;
}>;


export type ConsoleUserSessionsQuery = { user: { id: string, sessions: { pageInfo: { hasPreviousPage: boolean, hasNextPage: boolean, startCursor: string | null, endCursor: string | null }, edges: Array<{ cursor: string, node: { id: string, deviceName: string | null, deviceType: string | null, osName: string | null, osVersion: string | null, browserName: string | null, browserVersion: string | null, ipAddress: string | null, lastActiveAt: string | null, createdAt: string } }> } } | null };

export type ConsoleResetUserPasswordMutationVariables = Exact<{
  input: UserStateInput;
}>;


export type ConsoleResetUserPasswordMutation = { resetUserPassword: { userId: string, version: string, temporaryPassword: string } };

export type ConsoleResetUserMfaMutationVariables = Exact<{
  input: UserStateInput;
}>;


export type ConsoleResetUserMfaMutation = { resetUserMfa: { userId: string, version: string } };

export type ConsoleRevokeUserSessionsMutationVariables = Exact<{
  input: RevokeUserSessionsInput;
}>;


export type ConsoleRevokeUserSessionsMutation = { revokeUserSessions: { userId: string, version: string } };

export type ConsoleDeleteUserMutationVariables = Exact<{
  input: UserStateInput;
}>;


export type ConsoleDeleteUserMutation = { deleteUser: { deletedUserId: string } };

export class TypedDocumentString<TResult, TVariables>
  extends String
  implements DocumentTypeDecoration<TResult, TVariables>
{
  __apiType?: NonNullable<DocumentTypeDecoration<TResult, TVariables>['__apiType']>;
  private value: string;
  public __meta__?: Record<string, any> | undefined;

  constructor(value: string, __meta__?: Record<string, any> | undefined) {
    super(value);
    this.value = value;
    this.__meta__ = __meta__;
  }

  override toString(): string & DocumentTypeDecoration<TResult, TVariables> {
    return this.value;
  }
}
export const ConsoleClientAdvancedSettingsFieldsFragmentDoc = new TypedDocumentString(`
    fragment ConsoleClientAdvancedSettingsFields on ClientAdvancedSettings {
  frontchannelLogoutUri
  frontchannelLogoutSessionRequired
  backchannelLogoutUri
  backchannelLogoutSessionRequired
  logoUri
  clientUri
  policyUri
  tosUri
  contacts
  subjectType
  sectorIdentifierUri
  defaultMaxAge
  requireAuthTime
  defaultAcrValues
  idTokenSignedResponseAlgs
  idTokenEncryptedResponseAlgs
  idTokenEncryptedResponseEncs
  userinfoSignedResponseAlgs
  userinfoEncryptedResponseAlgs
  userinfoEncryptedResponseEncs
  requestObjectSigningAlgs
  requestObjectEncryptionAlgs
  requestObjectEncryptionEncs
  requestUris
  tokenEndpointAuthSigningAlgs
  initiateLoginUri
}
    `, {"fragmentName":"ConsoleClientAdvancedSettingsFields"}) as unknown as TypedDocumentString<ConsoleClientAdvancedSettingsFieldsFragment, unknown>;
export const ConsoleClientFieldsFragmentDoc = new TypedDocumentString(`
    fragment ConsoleClientFields on Client {
  id
  name
  description
  names {
    locale
    value
  }
  descriptions {
    locale
    value
  }
  builtIn
  enabled
  platforms {
    platform
    redirectUris
  }
  postLogoutRedirectUris
  grantTypes
  allowPublicClientFlow
  requirePushedAuthorizationRequests
  skipConsent
  corsEnabled
  oauthVersion
  includeScopedClaimsInIdToken
  includeScopedClaimsInAccessToken
  advancedSettings {
    ...ConsoleClientAdvancedSettingsFields
  }
  corsOrigins
  version
  createdAt
  updatedAt
}
    fragment ConsoleClientAdvancedSettingsFields on ClientAdvancedSettings {
  frontchannelLogoutUri
  frontchannelLogoutSessionRequired
  backchannelLogoutUri
  backchannelLogoutSessionRequired
  logoUri
  clientUri
  policyUri
  tosUri
  contacts
  subjectType
  sectorIdentifierUri
  defaultMaxAge
  requireAuthTime
  defaultAcrValues
  idTokenSignedResponseAlgs
  idTokenEncryptedResponseAlgs
  idTokenEncryptedResponseEncs
  userinfoSignedResponseAlgs
  userinfoEncryptedResponseAlgs
  userinfoEncryptedResponseEncs
  requestObjectSigningAlgs
  requestObjectEncryptionAlgs
  requestObjectEncryptionEncs
  requestUris
  tokenEndpointAuthSigningAlgs
  initiateLoginUri
}`, {"fragmentName":"ConsoleClientFields"}) as unknown as TypedDocumentString<ConsoleClientFieldsFragment, unknown>;
export const AuditEventFieldsFragmentDoc = new TypedDocumentString(`
    fragment AuditEventFields on AuditEvent {
  id
  occurredAt
  category
  action
  outcome
  failureReason
  actor {
    kind
    id
    oid
    label
    user @include(if: $includeActorUser) {
      id
      username
      email
      nickname
    }
    client @include(if: $includeActorClient) {
      id
      name
      names {
        locale
        value
      }
    }
  }
  target {
    kind
    id
    oid
    label
  }
  clientId
  authMethods
  ipAddress
  userAgent
  requestId
  traceId
  changes {
    field
    kind
    oldValue
    newValue
    added
    removed
  }
}
    `, {"fragmentName":"AuditEventFields"}) as unknown as TypedDocumentString<AuditEventFieldsFragment, unknown>;
export const ConsoleKeyFieldsFragmentDoc = new TypedDocumentString(`
    fragment ConsoleKeyFields on Key {
  id
  keyId
  use
  status
  inUse
  algorithms
  keyIds
  hasCertificate
  rotatedFromId
  createdAt
  expiresAt
  rotatedAt
  revokedAt
}
    `, {"fragmentName":"ConsoleKeyFields"}) as unknown as TypedDocumentString<ConsoleKeyFieldsFragment, unknown>;
export const ConsoleLocalizedEmailTemplateFieldsFragmentDoc = new TypedDocumentString(`
    fragment ConsoleLocalizedEmailTemplateFields on LocalizedEmailTemplate {
  default {
    subject
    html
  }
  translations {
    locale
    content {
      subject
      html
    }
  }
}
    `, {"fragmentName":"ConsoleLocalizedEmailTemplateFields"}) as unknown as TypedDocumentString<ConsoleLocalizedEmailTemplateFieldsFragment, unknown>;
export const ConsoleInstanceSettingsFieldsFragmentDoc = new TypedDocumentString(`
    fragment ConsoleInstanceSettingsFields on InstanceSettings {
  general {
    issuer
    loginUrl
    consoleUrl
    initializedAt
  }
  protocol {
    oauthVersion
    requirePushedAuthorizationRequests
    pushedAuthorizationRequestLifetimeSeconds
    pushedAuthorizationRequestLifetimeRange {
      min
      max
    }
    deviceAuthorizationRequestLifetimeSeconds
    deviceAuthorizationRequestLifetimeRange {
      min
      max
    }
    deviceAuthorizationPollingIntervalSeconds
    deviceAuthorizationPollingIntervalRange {
      min
      max
    }
    dynamicRegistrationEnabled
    accessTokenLifetimeSeconds
    accessTokenLifetimeRange {
      min
      max
    }
    idTokenLifetimeSeconds
    idTokenLifetimeRange {
      min
      max
    }
    refreshTokenLifetimeDays
    refreshTokenLifetimeDaysRange {
      min
      max
    }
    authorizationCodeLifetimeSeconds
    authorizationCodeLifetimeRange {
      min
      max
    }
    version
  }
  authentication {
    breachedPasswordCheckEnabled
    identifierEnumerationAllowed
    emailSignInEnabled
    passwordResetEnabled
    registrationEnabled
    passwordMaxAgeDays
    passwordMaxAgeDaysRange {
      min
      max
    }
    passwordHistoryCount
    passwordHistoryCountRange {
      min
      max
    }
    passwordMinLength
    passwordMinLengthRange {
      min
      max
    }
    maxFailedAttempts
    maxFailedAttemptsRange {
      min
      max
    }
    lockoutDurationMinutes
    lockoutDurationMinutesRange {
      min
      max
    }
    passwordHashing {
      timeCost
      timeCostRange {
        min
        max
      }
      memoryCostKib
      memoryCostKibRange {
        min
        max
      }
      parallelism
      parallelismRange {
        min
        max
      }
    }
    version
  }
  session {
    sessionLifetimeHours
    sessionLifetimeHoursRange {
      min
      max
    }
    elevatedAuthenticationLifetimeMinutes
    elevatedAuthenticationLifetimeMinutesRange {
      min
      max
    }
    recentAuthenticationLifetimeMinutes
    recentAuthenticationLifetimeMinutesRange {
      min
      max
    }
    loginLifetimeMinutes
    loginLifetimeMinutesRange {
      min
      max
    }
    version
  }
  email {
    delivery {
      enabled
      host
      port
      portRange {
        min
        max
      }
      security
      senderAddress
      senderName
      authentication {
        method
        username
        passwordSet
        tokenEndpoint
        clientId
        clientSecretSet
        grant
        refreshTokenSet
        scope
      }
      configured
      version
    }
    policy {
      signInCodeLifetimeMinutes
      signInCodeLifetimeMinutesRange {
        min
        max
      }
      passwordResetLifetimeMinutes
      passwordResetLifetimeMinutesRange {
        min
        max
      }
      registrationLifetimeMinutes
      registrationLifetimeMinutesRange {
        min
        max
      }
      emailVerificationLifetimeHours
      emailVerificationLifetimeHoursRange {
        min
        max
      }
      userInvitationLifetimeDays
      userInvitationLifetimeDaysRange {
        min
        max
      }
      resendIntervalSeconds
      resendIntervalSecondsRange {
        min
        max
      }
      loginMaxSends
      loginMaxSendsRange {
        min
        max
      }
      verificationMaxSends
      verificationMaxSendsRange {
        min
        max
      }
      verificationSendWindowHours
      verificationSendWindowHoursRange {
        min
        max
      }
      version
    }
    templates {
      kind
      variables
      previewScenarios
      customized
      version
      content {
        ...ConsoleLocalizedEmailTemplateFields
      }
      builtIn {
        ...ConsoleLocalizedEmailTemplateFields
      }
    }
  }
}
    fragment ConsoleLocalizedEmailTemplateFields on LocalizedEmailTemplate {
  default {
    subject
    html
  }
  translations {
    locale
    content {
      subject
      html
    }
  }
}`, {"fragmentName":"ConsoleInstanceSettingsFields"}) as unknown as TypedDocumentString<ConsoleInstanceSettingsFieldsFragment, unknown>;
export const ConsoleBootstrapDocument = new TypedDocumentString(`
    query ConsoleBootstrap {
  effectivePermissions {
    requestableScopes
    grantedScopes
    effectiveScopes
    authentication {
      acr
      authTime
      aal2
      recent
    }
  }
  instanceInfo {
    name
    environment
    issuer
    version
  }
}
    `) as unknown as TypedDocumentString<ConsoleBootstrapQuery, ConsoleBootstrapQueryVariables>;
export const ConsoleAccountThemeDocument = new TypedDocumentString(`
    query ConsoleAccountTheme {
  account {
    id
    theme
    locale
    zoneInfo
  }
}
    `) as unknown as TypedDocumentString<ConsoleAccountThemeQuery, ConsoleAccountThemeQueryVariables>;
export const ConsoleClientsDocument = new TypedDocumentString(`
    query ConsoleClients($filter: ClientFilter, $orderBy: ClientOrder, $first: Int, $after: String, $last: Int, $before: String) {
  clients(
    filter: $filter
    orderBy: $orderBy
    first: $first
    after: $after
    last: $last
    before: $before
  ) {
    totalCount
    pageInfo {
      hasNextPage
      hasPreviousPage
      startCursor
      endCursor
    }
    edges {
      cursor
      node {
        id
        name
        names {
          locale
          value
        }
        builtIn
        enabled
        version
        createdAt
      }
    }
  }
}
    `) as unknown as TypedDocumentString<ConsoleClientsQuery, ConsoleClientsQueryVariables>;
export const ConsoleClientDocument = new TypedDocumentString(`
    query ConsoleClient($id: ID!) {
  client(id: $id) {
    ...ConsoleClientFields
  }
}
    fragment ConsoleClientAdvancedSettingsFields on ClientAdvancedSettings {
  frontchannelLogoutUri
  frontchannelLogoutSessionRequired
  backchannelLogoutUri
  backchannelLogoutSessionRequired
  logoUri
  clientUri
  policyUri
  tosUri
  contacts
  subjectType
  sectorIdentifierUri
  defaultMaxAge
  requireAuthTime
  defaultAcrValues
  idTokenSignedResponseAlgs
  idTokenEncryptedResponseAlgs
  idTokenEncryptedResponseEncs
  userinfoSignedResponseAlgs
  userinfoEncryptedResponseAlgs
  userinfoEncryptedResponseEncs
  requestObjectSigningAlgs
  requestObjectEncryptionAlgs
  requestObjectEncryptionEncs
  requestUris
  tokenEndpointAuthSigningAlgs
  initiateLoginUri
}
fragment ConsoleClientFields on Client {
  id
  name
  description
  names {
    locale
    value
  }
  descriptions {
    locale
    value
  }
  builtIn
  enabled
  platforms {
    platform
    redirectUris
  }
  postLogoutRedirectUris
  grantTypes
  allowPublicClientFlow
  requirePushedAuthorizationRequests
  skipConsent
  corsEnabled
  oauthVersion
  includeScopedClaimsInIdToken
  includeScopedClaimsInAccessToken
  advancedSettings {
    ...ConsoleClientAdvancedSettingsFields
  }
  corsOrigins
  version
  createdAt
  updatedAt
}`) as unknown as TypedDocumentString<ConsoleClientQuery, ConsoleClientQueryVariables>;
export const ConsoleClientCredentialsDocument = new TypedDocumentString(`
    query ConsoleClientCredentials($id: ID!) {
  client(id: $id) {
    id
    version
    credentials {
      id
      type
      hint
      expiresAt
      active
      createdAt
    }
  }
}
    `) as unknown as TypedDocumentString<ConsoleClientCredentialsQuery, ConsoleClientCredentialsQueryVariables>;
export const ConsoleClientKeyCoverageDocument = new TypedDocumentString(`
    query ConsoleClientKeyCoverage($id: ID!) {
  client(id: $id) {
    id
    tokenEndpointAuthMethods
    keyCoverage {
      encryptionAlgs
      verificationAlgs
      remoteKeys
      secret
    }
  }
}
    `) as unknown as TypedDocumentString<ConsoleClientKeyCoverageQuery, ConsoleClientKeyCoverageQueryVariables>;
export const ConsoleClientScopesDocument = new TypedDocumentString(`
    query ConsoleClientScopes($id: ID!, $orderBy: ScopeOrder, $first: Int, $after: String, $last: Int, $before: String) {
  client(id: $id) {
    id
    version
    scopes(
      orderBy: $orderBy
      first: $first
      after: $after
      last: $last
      before: $before
    ) {
      totalCount
      pageInfo {
        hasNextPage
        hasPreviousPage
        startCursor
        endCursor
      }
      edges {
        cursor
        clientGranted
        node {
          id
          code
          name
          names {
            locale
            value
          }
          resourceId
          builtIn
          enabled
        }
      }
    }
  }
}
    `) as unknown as TypedDocumentString<ConsoleClientScopesQuery, ConsoleClientScopesQueryVariables>;
export const ConsoleProtocolScopesDocument = new TypedDocumentString(`
    query ConsoleProtocolScopes($first: Int, $after: String) {
  scopes(
    filter: { protocolOnly: true, enabled: true }
    orderBy: CODE_ASC
    first: $first
    after: $after
  ) {
    pageInfo {
      hasNextPage
      endCursor
    }
    edges {
      node {
        id
        code
        name
        names {
          locale
          value
        }
        description
        descriptions {
          locale
          value
        }
      }
    }
  }
}
    `) as unknown as TypedDocumentString<ConsoleProtocolScopesQuery, ConsoleProtocolScopesQueryVariables>;
export const ConsoleCreateClientDocument = new TypedDocumentString(`
    mutation ConsoleCreateClient($input: CreateClientInput!) {
  createClient(input: $input) {
    clientId
    version
  }
}
    `) as unknown as TypedDocumentString<ConsoleCreateClientMutation, ConsoleCreateClientMutationVariables>;
export const ConsoleUpdateClientDocument = new TypedDocumentString(`
    mutation ConsoleUpdateClient($input: UpdateClientInput!) {
  updateClient(input: $input) {
    clientId
    version
  }
}
    `) as unknown as TypedDocumentString<ConsoleUpdateClientMutation, ConsoleUpdateClientMutationVariables>;
export const ConsoleEnableClientDocument = new TypedDocumentString(`
    mutation ConsoleEnableClient($input: ClientStateInput!) {
  enableClient(input: $input) {
    clientId
    version
  }
}
    `) as unknown as TypedDocumentString<ConsoleEnableClientMutation, ConsoleEnableClientMutationVariables>;
export const ConsoleDisableClientDocument = new TypedDocumentString(`
    mutation ConsoleDisableClient($input: ClientStateInput!) {
  disableClient(input: $input) {
    clientId
    version
  }
}
    `) as unknown as TypedDocumentString<ConsoleDisableClientMutation, ConsoleDisableClientMutationVariables>;
export const ConsoleDeleteClientDocument = new TypedDocumentString(`
    mutation ConsoleDeleteClient($input: ClientStateInput!) {
  deleteClient(input: $input) {
    clientId
    deleted
  }
}
    `) as unknown as TypedDocumentString<ConsoleDeleteClientMutation, ConsoleDeleteClientMutationVariables>;
export const ConsoleCreateClientSecretDocument = new TypedDocumentString(`
    mutation ConsoleCreateClientSecret($input: CreateClientSecretInput!) {
  createClientSecret(input: $input) {
    clientId
    version
    secret
    credential {
      id
      hint
      expiresAt
    }
  }
}
    `) as unknown as TypedDocumentString<ConsoleCreateClientSecretMutation, ConsoleCreateClientSecretMutationVariables>;
export const ConsoleRotateClientSecretDocument = new TypedDocumentString(`
    mutation ConsoleRotateClientSecret($input: RotateClientSecretInput!) {
  rotateClientSecret(input: $input) {
    clientId
    version
    secret
    credential {
      id
      hint
      expiresAt
    }
  }
}
    `) as unknown as TypedDocumentString<ConsoleRotateClientSecretMutation, ConsoleRotateClientSecretMutationVariables>;
export const ConsoleAddClientPublicKeyDocument = new TypedDocumentString(`
    mutation ConsoleAddClientPublicKey($input: AddClientPublicKeyInput!) {
  addClientPublicKey(input: $input) {
    clientId
    version
  }
}
    `) as unknown as TypedDocumentString<ConsoleAddClientPublicKeyMutation, ConsoleAddClientPublicKeyMutationVariables>;
export const ConsoleAddClientJwksUriDocument = new TypedDocumentString(`
    mutation ConsoleAddClientJwksUri($input: AddClientJwksUriInput!) {
  addClientJwksUri(input: $input) {
    clientId
    version
  }
}
    `) as unknown as TypedDocumentString<ConsoleAddClientJwksUriMutation, ConsoleAddClientJwksUriMutationVariables>;
export const ConsoleRevokeClientCredentialDocument = new TypedDocumentString(`
    mutation ConsoleRevokeClientCredential($input: RevokeClientCredentialInput!) {
  revokeClientCredential(input: $input) {
    clientId
    version
  }
}
    `) as unknown as TypedDocumentString<ConsoleRevokeClientCredentialMutation, ConsoleRevokeClientCredentialMutationVariables>;
export const ConsoleSetClientScopesDocument = new TypedDocumentString(`
    mutation ConsoleSetClientScopes($input: SetClientScopesInput!) {
  setClientScopes(input: $input) {
    clientId
    version
    scopeIds
    clientGrantedScopeIds
  }
}
    `) as unknown as TypedDocumentString<ConsoleSetClientScopesMutation, ConsoleSetClientScopesMutationVariables>;
export const ConsoleClientEndpointsDocument = new TypedDocumentString(`
    query ConsoleClientEndpoints {
  instanceMetadata {
    issuer
    openidConfigurationUrl
    oauthAuthorizationServerMetadataUrl
    jwksUri
    authorizationEndpoint
    tokenEndpoint
    pushedAuthorizationRequestEndpoint
    userinfoEndpoint
    deviceAuthorizationEndpoint
    revocationEndpoint
    introspectionEndpoint
    endSessionEndpoint
    checkSessionIframe
    registrationEndpoint
  }
}
    `) as unknown as TypedDocumentString<ConsoleClientEndpointsQuery, ConsoleClientEndpointsQueryVariables>;
export const ConsoleClientMetadataOptionsDocument = new TypedDocumentString(`
    query ConsoleClientMetadataOptions {
  clientMetadataOptions {
    subjectTypes
    acrValues
    idTokenSigningAlgs
    idTokenEncryptionAlgs
    idTokenEncryptionEncs
    userinfoSigningAlgs
    userinfoEncryptionAlgs
    userinfoEncryptionEncs
    requestObjectSigningAlgs
    requestObjectEncryptionAlgs
    requestObjectEncryptionEncs
    tokenEndpointAuthSigningAlgs
    activeSigningAlgs
    activeRequestObjectEncryptionAlgs
  }
}
    `) as unknown as TypedDocumentString<ConsoleClientMetadataOptionsQuery, ConsoleClientMetadataOptionsQueryVariables>;
export const ConsoleResourcesDocument = new TypedDocumentString(`
    query ConsoleResources($filter: ResourceFilter, $orderBy: ResourceOrder, $first: Int, $after: String, $last: Int, $before: String) {
  resources(
    filter: $filter
    orderBy: $orderBy
    first: $first
    after: $after
    last: $last
    before: $before
  ) {
    pageInfo {
      hasNextPage
      hasPreviousPage
      startCursor
      endCursor
    }
    edges {
      cursor
      node {
        id
        name
        uri
        enabled
        createdAt
        updatedAt
      }
    }
  }
}
    `) as unknown as TypedDocumentString<ConsoleResourcesQuery, ConsoleResourcesQueryVariables>;
export const ConsoleResourceDocument = new TypedDocumentString(`
    query ConsoleResource($id: ID!) {
  resource(id: $id) {
    id
    name
    uri
    enabled
    version
    createdAt
    updatedAt
  }
}
    `) as unknown as TypedDocumentString<ConsoleResourceQuery, ConsoleResourceQueryVariables>;
export const ConsolePermissionRolesDocument = new TypedDocumentString(`
    query ConsolePermissionRoles($id: ID!, $first: Int, $after: String, $last: Int, $before: String) {
  permission: scope(id: $id) {
    id
    roles(first: $first, after: $after, last: $last, before: $before) {
      pageInfo {
        hasNextPage
        hasPreviousPage
        startCursor
        endCursor
      }
      edges {
        node {
          id
          name
          builtIn
          enabled
          description
          names {
            locale
            value
          }
        }
      }
    }
  }
}
    `) as unknown as TypedDocumentString<ConsolePermissionRolesQuery, ConsolePermissionRolesQueryVariables>;
export const ConsolePermissionDocument = new TypedDocumentString(`
    query ConsolePermission($id: ID!, $includeResource: Boolean!) {
  permission: scope(id: $id) {
    id
    resourceId
    code
    name
    description
    builtIn
    names {
      locale
      value
    }
    descriptions {
      locale
      value
    }
    enabled
    version
    createdAt
    updatedAt
    resource @include(if: $includeResource) {
      id
      uri
      name
      enabled
    }
  }
}
    `) as unknown as TypedDocumentString<ConsolePermissionQuery, ConsolePermissionQueryVariables>;
export const ConsoleCreatePermissionDocument = new TypedDocumentString(`
    mutation ConsoleCreatePermission($input: CreateScopeInput!) {
  createPermission: createScope(input: $input) {
    permissionId: scopeId
    version
  }
}
    `) as unknown as TypedDocumentString<ConsoleCreatePermissionMutation, ConsoleCreatePermissionMutationVariables>;
export const ConsoleUpdatePermissionDocument = new TypedDocumentString(`
    mutation ConsoleUpdatePermission($input: UpdateScopeInput!) {
  updatePermission: updateScope(input: $input) {
    permissionId: scopeId
    version
  }
}
    `) as unknown as TypedDocumentString<ConsoleUpdatePermissionMutation, ConsoleUpdatePermissionMutationVariables>;
export const ConsoleEnablePermissionDocument = new TypedDocumentString(`
    mutation ConsoleEnablePermission($input: ScopeStateInput!) {
  enablePermission: enableScope(input: $input) {
    permissionId: scopeId
    version
  }
}
    `) as unknown as TypedDocumentString<ConsoleEnablePermissionMutation, ConsoleEnablePermissionMutationVariables>;
export const ConsoleDisablePermissionDocument = new TypedDocumentString(`
    mutation ConsoleDisablePermission($input: ScopeStateInput!) {
  disablePermission: disableScope(input: $input) {
    permissionId: scopeId
    version
  }
}
    `) as unknown as TypedDocumentString<ConsoleDisablePermissionMutation, ConsoleDisablePermissionMutationVariables>;
export const ConsoleScopesDocument = new TypedDocumentString(`
    query ConsoleScopes($filter: ScopeFilter, $first: Int, $after: String, $last: Int, $before: String) {
  scopes(
    filter: $filter
    orderBy: CODE_ASC
    first: $first
    after: $after
    last: $last
    before: $before
  ) {
    pageInfo {
      hasNextPage
      hasPreviousPage
      startCursor
      endCursor
    }
    edges {
      cursor
      node {
        id
        code
        name
        description
        names {
          locale
          value
        }
      }
    }
  }
}
    `) as unknown as TypedDocumentString<ConsoleScopesQuery, ConsoleScopesQueryVariables>;
export const ConsolePermissionsDocument = new TypedDocumentString(`
    query ConsolePermissions($filter: ScopeFilter, $orderBy: ScopeOrder, $first: Int, $after: String, $last: Int, $before: String, $includeResource: Boolean!) {
  permissions: scopes(
    filter: $filter
    orderBy: $orderBy
    first: $first
    after: $after
    last: $last
    before: $before
  ) {
    totalCount
    pageInfo {
      hasNextPage
      hasPreviousPage
      startCursor
      endCursor
    }
    edges {
      cursor
      node {
        id
        resourceId
        code
        name
        description
        builtIn
        names {
          locale
          value
        }
        descriptions {
          locale
          value
        }
        enabled
        version
        createdAt
        updatedAt
        resource @include(if: $includeResource) {
          id
          uri
          name
          enabled
        }
      }
    }
  }
}
    `) as unknown as TypedDocumentString<ConsolePermissionsQuery, ConsolePermissionsQueryVariables>;
export const ConsoleResourcePermissionsDocument = new TypedDocumentString(`
    query ConsoleResourcePermissions($filter: ScopeFilter, $orderBy: ScopeOrder, $first: Int, $after: String, $last: Int, $before: String) {
  permissions: scopes(
    filter: $filter
    orderBy: $orderBy
    first: $first
    after: $after
    last: $last
    before: $before
  ) {
    totalCount
    pageInfo {
      hasNextPage
      hasPreviousPage
      startCursor
      endCursor
    }
    edges {
      cursor
      node {
        id
        code
        name
        description
        builtIn
        enabled
        createdAt
        names {
          locale
          value
        }
        descriptions {
          locale
          value
        }
      }
    }
  }
}
    `) as unknown as TypedDocumentString<ConsoleResourcePermissionsQuery, ConsoleResourcePermissionsQueryVariables>;
export const InstanceDashboardDocument = new TypedDocumentString(`
    query InstanceDashboard($timeZone: String!, $includeUsers: Boolean!, $includeClients: Boolean!, $includeSessions: Boolean!, $includeResources: Boolean!) {
  instanceOverview {
    generatedAt
    users(timeZone: $timeZone) @include(if: $includeUsers) {
      total
      enabled
      createdLast7Days
      registrations {
        date
        count
      }
    }
    clients @include(if: $includeClients) {
      total
      enabled
      builtIn
    }
    sessions @include(if: $includeSessions) {
      active
      createdLast24Hours
    }
    resources @include(if: $includeResources) {
      total
      enabled
    }
  }
}
    `) as unknown as TypedDocumentString<InstanceDashboardQuery, InstanceDashboardQueryVariables>;
export const AuditEventsQueryDocument = new TypedDocumentString(`
    query AuditEventsQuery($query: String, $timeZone: String, $orderBy: AuditEventOrder, $first: Int, $after: String, $last: Int, $before: String, $includeActorUser: Boolean!, $includeActorClient: Boolean!) {
  auditEvents(
    query: $query
    timeZone: $timeZone
    orderBy: $orderBy
    first: $first
    after: $after
    last: $last
    before: $before
  ) {
    totalCount
    pageInfo {
      hasPreviousPage
      hasNextPage
      startCursor
      endCursor
    }
    edges {
      cursor
      node {
        ...AuditEventFields
      }
    }
  }
}
    fragment AuditEventFields on AuditEvent {
  id
  occurredAt
  category
  action
  outcome
  failureReason
  actor {
    kind
    id
    oid
    label
    user @include(if: $includeActorUser) {
      id
      username
      email
      nickname
    }
    client @include(if: $includeActorClient) {
      id
      name
      names {
        locale
        value
      }
    }
  }
  target {
    kind
    id
    oid
    label
  }
  clientId
  authMethods
  ipAddress
  userAgent
  requestId
  traceId
  changes {
    field
    kind
    oldValue
    newValue
    added
    removed
  }
}`) as unknown as TypedDocumentString<AuditEventsQueryQuery, AuditEventsQueryQueryVariables>;
export const AuditEventDetailQueryDocument = new TypedDocumentString(`
    query AuditEventDetailQuery($id: ID!, $includeActorUser: Boolean!, $includeActorClient: Boolean!) {
  auditEvent(id: $id) {
    ...AuditEventFields
    client @include(if: $includeActorClient) {
      id
      name
      names {
        locale
        value
      }
    }
    device {
      browser
      browserVersion
      os
      osVersion
    }
  }
}
    fragment AuditEventFields on AuditEvent {
  id
  occurredAt
  category
  action
  outcome
  failureReason
  actor {
    kind
    id
    oid
    label
    user @include(if: $includeActorUser) {
      id
      username
      email
      nickname
    }
    client @include(if: $includeActorClient) {
      id
      name
      names {
        locale
        value
      }
    }
  }
  target {
    kind
    id
    oid
    label
  }
  clientId
  authMethods
  ipAddress
  userAgent
  requestId
  traceId
  changes {
    field
    kind
    oldValue
    newValue
    added
    removed
  }
}`) as unknown as TypedDocumentString<AuditEventDetailQueryQuery, AuditEventDetailQueryQueryVariables>;
export const ConsoleUpdateEmailDeliverySettingsDocument = new TypedDocumentString(`
    mutation ConsoleUpdateEmailDeliverySettings($input: UpdateEmailDeliverySettingsInput!) {
  updateEmailDeliverySettings(input: $input) {
    clientMutationId
    settings {
      ...ConsoleInstanceSettingsFields
    }
  }
}
    fragment ConsoleInstanceSettingsFields on InstanceSettings {
  general {
    issuer
    loginUrl
    consoleUrl
    initializedAt
  }
  protocol {
    oauthVersion
    requirePushedAuthorizationRequests
    pushedAuthorizationRequestLifetimeSeconds
    pushedAuthorizationRequestLifetimeRange {
      min
      max
    }
    deviceAuthorizationRequestLifetimeSeconds
    deviceAuthorizationRequestLifetimeRange {
      min
      max
    }
    deviceAuthorizationPollingIntervalSeconds
    deviceAuthorizationPollingIntervalRange {
      min
      max
    }
    dynamicRegistrationEnabled
    accessTokenLifetimeSeconds
    accessTokenLifetimeRange {
      min
      max
    }
    idTokenLifetimeSeconds
    idTokenLifetimeRange {
      min
      max
    }
    refreshTokenLifetimeDays
    refreshTokenLifetimeDaysRange {
      min
      max
    }
    authorizationCodeLifetimeSeconds
    authorizationCodeLifetimeRange {
      min
      max
    }
    version
  }
  authentication {
    breachedPasswordCheckEnabled
    identifierEnumerationAllowed
    emailSignInEnabled
    passwordResetEnabled
    registrationEnabled
    passwordMaxAgeDays
    passwordMaxAgeDaysRange {
      min
      max
    }
    passwordHistoryCount
    passwordHistoryCountRange {
      min
      max
    }
    passwordMinLength
    passwordMinLengthRange {
      min
      max
    }
    maxFailedAttempts
    maxFailedAttemptsRange {
      min
      max
    }
    lockoutDurationMinutes
    lockoutDurationMinutesRange {
      min
      max
    }
    passwordHashing {
      timeCost
      timeCostRange {
        min
        max
      }
      memoryCostKib
      memoryCostKibRange {
        min
        max
      }
      parallelism
      parallelismRange {
        min
        max
      }
    }
    version
  }
  session {
    sessionLifetimeHours
    sessionLifetimeHoursRange {
      min
      max
    }
    elevatedAuthenticationLifetimeMinutes
    elevatedAuthenticationLifetimeMinutesRange {
      min
      max
    }
    recentAuthenticationLifetimeMinutes
    recentAuthenticationLifetimeMinutesRange {
      min
      max
    }
    loginLifetimeMinutes
    loginLifetimeMinutesRange {
      min
      max
    }
    version
  }
  email {
    delivery {
      enabled
      host
      port
      portRange {
        min
        max
      }
      security
      senderAddress
      senderName
      authentication {
        method
        username
        passwordSet
        tokenEndpoint
        clientId
        clientSecretSet
        grant
        refreshTokenSet
        scope
      }
      configured
      version
    }
    policy {
      signInCodeLifetimeMinutes
      signInCodeLifetimeMinutesRange {
        min
        max
      }
      passwordResetLifetimeMinutes
      passwordResetLifetimeMinutesRange {
        min
        max
      }
      registrationLifetimeMinutes
      registrationLifetimeMinutesRange {
        min
        max
      }
      emailVerificationLifetimeHours
      emailVerificationLifetimeHoursRange {
        min
        max
      }
      userInvitationLifetimeDays
      userInvitationLifetimeDaysRange {
        min
        max
      }
      resendIntervalSeconds
      resendIntervalSecondsRange {
        min
        max
      }
      loginMaxSends
      loginMaxSendsRange {
        min
        max
      }
      verificationMaxSends
      verificationMaxSendsRange {
        min
        max
      }
      verificationSendWindowHours
      verificationSendWindowHoursRange {
        min
        max
      }
      version
    }
    templates {
      kind
      variables
      previewScenarios
      customized
      version
      content {
        ...ConsoleLocalizedEmailTemplateFields
      }
      builtIn {
        ...ConsoleLocalizedEmailTemplateFields
      }
    }
  }
}
fragment ConsoleLocalizedEmailTemplateFields on LocalizedEmailTemplate {
  default {
    subject
    html
  }
  translations {
    locale
    content {
      subject
      html
    }
  }
}`) as unknown as TypedDocumentString<ConsoleUpdateEmailDeliverySettingsMutation, ConsoleUpdateEmailDeliverySettingsMutationVariables>;
export const ConsoleUpdateEmailPolicySettingsDocument = new TypedDocumentString(`
    mutation ConsoleUpdateEmailPolicySettings($input: UpdateEmailPolicySettingsInput!) {
  updateEmailPolicySettings(input: $input) {
    clientMutationId
    settings {
      ...ConsoleInstanceSettingsFields
    }
  }
}
    fragment ConsoleInstanceSettingsFields on InstanceSettings {
  general {
    issuer
    loginUrl
    consoleUrl
    initializedAt
  }
  protocol {
    oauthVersion
    requirePushedAuthorizationRequests
    pushedAuthorizationRequestLifetimeSeconds
    pushedAuthorizationRequestLifetimeRange {
      min
      max
    }
    deviceAuthorizationRequestLifetimeSeconds
    deviceAuthorizationRequestLifetimeRange {
      min
      max
    }
    deviceAuthorizationPollingIntervalSeconds
    deviceAuthorizationPollingIntervalRange {
      min
      max
    }
    dynamicRegistrationEnabled
    accessTokenLifetimeSeconds
    accessTokenLifetimeRange {
      min
      max
    }
    idTokenLifetimeSeconds
    idTokenLifetimeRange {
      min
      max
    }
    refreshTokenLifetimeDays
    refreshTokenLifetimeDaysRange {
      min
      max
    }
    authorizationCodeLifetimeSeconds
    authorizationCodeLifetimeRange {
      min
      max
    }
    version
  }
  authentication {
    breachedPasswordCheckEnabled
    identifierEnumerationAllowed
    emailSignInEnabled
    passwordResetEnabled
    registrationEnabled
    passwordMaxAgeDays
    passwordMaxAgeDaysRange {
      min
      max
    }
    passwordHistoryCount
    passwordHistoryCountRange {
      min
      max
    }
    passwordMinLength
    passwordMinLengthRange {
      min
      max
    }
    maxFailedAttempts
    maxFailedAttemptsRange {
      min
      max
    }
    lockoutDurationMinutes
    lockoutDurationMinutesRange {
      min
      max
    }
    passwordHashing {
      timeCost
      timeCostRange {
        min
        max
      }
      memoryCostKib
      memoryCostKibRange {
        min
        max
      }
      parallelism
      parallelismRange {
        min
        max
      }
    }
    version
  }
  session {
    sessionLifetimeHours
    sessionLifetimeHoursRange {
      min
      max
    }
    elevatedAuthenticationLifetimeMinutes
    elevatedAuthenticationLifetimeMinutesRange {
      min
      max
    }
    recentAuthenticationLifetimeMinutes
    recentAuthenticationLifetimeMinutesRange {
      min
      max
    }
    loginLifetimeMinutes
    loginLifetimeMinutesRange {
      min
      max
    }
    version
  }
  email {
    delivery {
      enabled
      host
      port
      portRange {
        min
        max
      }
      security
      senderAddress
      senderName
      authentication {
        method
        username
        passwordSet
        tokenEndpoint
        clientId
        clientSecretSet
        grant
        refreshTokenSet
        scope
      }
      configured
      version
    }
    policy {
      signInCodeLifetimeMinutes
      signInCodeLifetimeMinutesRange {
        min
        max
      }
      passwordResetLifetimeMinutes
      passwordResetLifetimeMinutesRange {
        min
        max
      }
      registrationLifetimeMinutes
      registrationLifetimeMinutesRange {
        min
        max
      }
      emailVerificationLifetimeHours
      emailVerificationLifetimeHoursRange {
        min
        max
      }
      userInvitationLifetimeDays
      userInvitationLifetimeDaysRange {
        min
        max
      }
      resendIntervalSeconds
      resendIntervalSecondsRange {
        min
        max
      }
      loginMaxSends
      loginMaxSendsRange {
        min
        max
      }
      verificationMaxSends
      verificationMaxSendsRange {
        min
        max
      }
      verificationSendWindowHours
      verificationSendWindowHoursRange {
        min
        max
      }
      version
    }
    templates {
      kind
      variables
      previewScenarios
      customized
      version
      content {
        ...ConsoleLocalizedEmailTemplateFields
      }
      builtIn {
        ...ConsoleLocalizedEmailTemplateFields
      }
    }
  }
}
fragment ConsoleLocalizedEmailTemplateFields on LocalizedEmailTemplate {
  default {
    subject
    html
  }
  translations {
    locale
    content {
      subject
      html
    }
  }
}`) as unknown as TypedDocumentString<ConsoleUpdateEmailPolicySettingsMutation, ConsoleUpdateEmailPolicySettingsMutationVariables>;
export const ConsoleUpdateEmailTemplateDocument = new TypedDocumentString(`
    mutation ConsoleUpdateEmailTemplate($input: UpdateEmailTemplateInput!) {
  updateEmailTemplate(input: $input) {
    clientMutationId
    settings {
      ...ConsoleInstanceSettingsFields
    }
  }
}
    fragment ConsoleInstanceSettingsFields on InstanceSettings {
  general {
    issuer
    loginUrl
    consoleUrl
    initializedAt
  }
  protocol {
    oauthVersion
    requirePushedAuthorizationRequests
    pushedAuthorizationRequestLifetimeSeconds
    pushedAuthorizationRequestLifetimeRange {
      min
      max
    }
    deviceAuthorizationRequestLifetimeSeconds
    deviceAuthorizationRequestLifetimeRange {
      min
      max
    }
    deviceAuthorizationPollingIntervalSeconds
    deviceAuthorizationPollingIntervalRange {
      min
      max
    }
    dynamicRegistrationEnabled
    accessTokenLifetimeSeconds
    accessTokenLifetimeRange {
      min
      max
    }
    idTokenLifetimeSeconds
    idTokenLifetimeRange {
      min
      max
    }
    refreshTokenLifetimeDays
    refreshTokenLifetimeDaysRange {
      min
      max
    }
    authorizationCodeLifetimeSeconds
    authorizationCodeLifetimeRange {
      min
      max
    }
    version
  }
  authentication {
    breachedPasswordCheckEnabled
    identifierEnumerationAllowed
    emailSignInEnabled
    passwordResetEnabled
    registrationEnabled
    passwordMaxAgeDays
    passwordMaxAgeDaysRange {
      min
      max
    }
    passwordHistoryCount
    passwordHistoryCountRange {
      min
      max
    }
    passwordMinLength
    passwordMinLengthRange {
      min
      max
    }
    maxFailedAttempts
    maxFailedAttemptsRange {
      min
      max
    }
    lockoutDurationMinutes
    lockoutDurationMinutesRange {
      min
      max
    }
    passwordHashing {
      timeCost
      timeCostRange {
        min
        max
      }
      memoryCostKib
      memoryCostKibRange {
        min
        max
      }
      parallelism
      parallelismRange {
        min
        max
      }
    }
    version
  }
  session {
    sessionLifetimeHours
    sessionLifetimeHoursRange {
      min
      max
    }
    elevatedAuthenticationLifetimeMinutes
    elevatedAuthenticationLifetimeMinutesRange {
      min
      max
    }
    recentAuthenticationLifetimeMinutes
    recentAuthenticationLifetimeMinutesRange {
      min
      max
    }
    loginLifetimeMinutes
    loginLifetimeMinutesRange {
      min
      max
    }
    version
  }
  email {
    delivery {
      enabled
      host
      port
      portRange {
        min
        max
      }
      security
      senderAddress
      senderName
      authentication {
        method
        username
        passwordSet
        tokenEndpoint
        clientId
        clientSecretSet
        grant
        refreshTokenSet
        scope
      }
      configured
      version
    }
    policy {
      signInCodeLifetimeMinutes
      signInCodeLifetimeMinutesRange {
        min
        max
      }
      passwordResetLifetimeMinutes
      passwordResetLifetimeMinutesRange {
        min
        max
      }
      registrationLifetimeMinutes
      registrationLifetimeMinutesRange {
        min
        max
      }
      emailVerificationLifetimeHours
      emailVerificationLifetimeHoursRange {
        min
        max
      }
      userInvitationLifetimeDays
      userInvitationLifetimeDaysRange {
        min
        max
      }
      resendIntervalSeconds
      resendIntervalSecondsRange {
        min
        max
      }
      loginMaxSends
      loginMaxSendsRange {
        min
        max
      }
      verificationMaxSends
      verificationMaxSendsRange {
        min
        max
      }
      verificationSendWindowHours
      verificationSendWindowHoursRange {
        min
        max
      }
      version
    }
    templates {
      kind
      variables
      previewScenarios
      customized
      version
      content {
        ...ConsoleLocalizedEmailTemplateFields
      }
      builtIn {
        ...ConsoleLocalizedEmailTemplateFields
      }
    }
  }
}
fragment ConsoleLocalizedEmailTemplateFields on LocalizedEmailTemplate {
  default {
    subject
    html
  }
  translations {
    locale
    content {
      subject
      html
    }
  }
}`) as unknown as TypedDocumentString<ConsoleUpdateEmailTemplateMutation, ConsoleUpdateEmailTemplateMutationVariables>;
export const ConsoleSendTestEmailDocument = new TypedDocumentString(`
    mutation ConsoleSendTestEmail($input: SendTestEmailInput!) {
  sendTestEmail(input: $input) {
    sent
    clientMutationId
  }
}
    `) as unknown as TypedDocumentString<ConsoleSendTestEmailMutation, ConsoleSendTestEmailMutationVariables>;
export const ConsoleEmailTemplatePreviewDocument = new TypedDocumentString(`
    query ConsoleEmailTemplatePreview($input: EmailTemplatePreviewInput!) {
  emailTemplatePreview(input: $input) {
    subject
    html
  }
}
    `) as unknown as TypedDocumentString<ConsoleEmailTemplatePreviewQuery, ConsoleEmailTemplatePreviewQueryVariables>;
export const ConsoleKeysDocument = new TypedDocumentString(`
    query ConsoleKeys($filter: KeyFilter, $first: Int, $after: String, $last: Int, $before: String) {
  keys(
    filter: $filter
    first: $first
    after: $after
    last: $last
    before: $before
  ) {
    totalCount
    pageInfo {
      hasNextPage
      hasPreviousPage
      startCursor
      endCursor
    }
    edges {
      cursor
      node {
        ...ConsoleKeyFields
      }
    }
  }
}
    fragment ConsoleKeyFields on Key {
  id
  keyId
  use
  status
  inUse
  algorithms
  keyIds
  hasCertificate
  rotatedFromId
  createdAt
  expiresAt
  rotatedAt
  revokedAt
}`) as unknown as TypedDocumentString<ConsoleKeysQuery, ConsoleKeysQueryVariables>;
export const ConsoleRotateKeyDocument = new TypedDocumentString(`
    mutation ConsoleRotateKey($input: KeyLifecycleInput!) {
  rotateKey(input: $input) {
    clientMutationId
    key {
      ...ConsoleKeyFields
    }
    successor {
      ...ConsoleKeyFields
    }
  }
}
    fragment ConsoleKeyFields on Key {
  id
  keyId
  use
  status
  inUse
  algorithms
  keyIds
  hasCertificate
  rotatedFromId
  createdAt
  expiresAt
  rotatedAt
  revokedAt
}`) as unknown as TypedDocumentString<ConsoleRotateKeyMutation, ConsoleRotateKeyMutationVariables>;
export const ConsoleRevokeKeyDocument = new TypedDocumentString(`
    mutation ConsoleRevokeKey($input: KeyLifecycleInput!) {
  revokeKey(input: $input) {
    clientMutationId
    key {
      ...ConsoleKeyFields
    }
  }
}
    fragment ConsoleKeyFields on Key {
  id
  keyId
  use
  status
  inUse
  algorithms
  keyIds
  hasCertificate
  rotatedFromId
  createdAt
  expiresAt
  rotatedAt
  revokedAt
}`) as unknown as TypedDocumentString<ConsoleRevokeKeyMutation, ConsoleRevokeKeyMutationVariables>;
export const ConsoleRotateAndRevokeKeyDocument = new TypedDocumentString(`
    mutation ConsoleRotateAndRevokeKey($input: KeyLifecycleInput!) {
  rotateAndRevokeKey(input: $input) {
    clientMutationId
    key {
      ...ConsoleKeyFields
    }
    successor {
      ...ConsoleKeyFields
    }
  }
}
    fragment ConsoleKeyFields on Key {
  id
  keyId
  use
  status
  inUse
  algorithms
  keyIds
  hasCertificate
  rotatedFromId
  createdAt
  expiresAt
  rotatedAt
  revokedAt
}`) as unknown as TypedDocumentString<ConsoleRotateAndRevokeKeyMutation, ConsoleRotateAndRevokeKeyMutationVariables>;
export const ConsoleJwksUriDocument = new TypedDocumentString(`
    query ConsoleJwksUri {
  instanceMetadata {
    jwksUri
  }
}
    `) as unknown as TypedDocumentString<ConsoleJwksUriQuery, ConsoleJwksUriQueryVariables>;
export const ConsoleCreateSigningKeyDocument = new TypedDocumentString(`
    mutation ConsoleCreateSigningKey($input: CreateSigningKeyInput!) {
  createSigningKey(input: $input) {
    clientMutationId
    key {
      ...ConsoleKeyFields
    }
  }
}
    fragment ConsoleKeyFields on Key {
  id
  keyId
  use
  status
  inUse
  algorithms
  keyIds
  hasCertificate
  rotatedFromId
  createdAt
  expiresAt
  rotatedAt
  revokedAt
}`) as unknown as TypedDocumentString<ConsoleCreateSigningKeyMutation, ConsoleCreateSigningKeyMutationVariables>;
export const ConsoleSigningKeyAlgorithmsDocument = new TypedDocumentString(`
    query ConsoleSigningKeyAlgorithms {
  signingKeyAlgorithms {
    algorithm
    keyAlgorithm
    keyName
  }
}
    `) as unknown as TypedDocumentString<ConsoleSigningKeyAlgorithmsQuery, ConsoleSigningKeyAlgorithmsQueryVariables>;
export const ConsoleInstanceSettingsDocument = new TypedDocumentString(`
    query ConsoleInstanceSettings {
  instanceSettings {
    ...ConsoleInstanceSettingsFields
  }
}
    fragment ConsoleInstanceSettingsFields on InstanceSettings {
  general {
    issuer
    loginUrl
    consoleUrl
    initializedAt
  }
  protocol {
    oauthVersion
    requirePushedAuthorizationRequests
    pushedAuthorizationRequestLifetimeSeconds
    pushedAuthorizationRequestLifetimeRange {
      min
      max
    }
    deviceAuthorizationRequestLifetimeSeconds
    deviceAuthorizationRequestLifetimeRange {
      min
      max
    }
    deviceAuthorizationPollingIntervalSeconds
    deviceAuthorizationPollingIntervalRange {
      min
      max
    }
    dynamicRegistrationEnabled
    accessTokenLifetimeSeconds
    accessTokenLifetimeRange {
      min
      max
    }
    idTokenLifetimeSeconds
    idTokenLifetimeRange {
      min
      max
    }
    refreshTokenLifetimeDays
    refreshTokenLifetimeDaysRange {
      min
      max
    }
    authorizationCodeLifetimeSeconds
    authorizationCodeLifetimeRange {
      min
      max
    }
    version
  }
  authentication {
    breachedPasswordCheckEnabled
    identifierEnumerationAllowed
    emailSignInEnabled
    passwordResetEnabled
    registrationEnabled
    passwordMaxAgeDays
    passwordMaxAgeDaysRange {
      min
      max
    }
    passwordHistoryCount
    passwordHistoryCountRange {
      min
      max
    }
    passwordMinLength
    passwordMinLengthRange {
      min
      max
    }
    maxFailedAttempts
    maxFailedAttemptsRange {
      min
      max
    }
    lockoutDurationMinutes
    lockoutDurationMinutesRange {
      min
      max
    }
    passwordHashing {
      timeCost
      timeCostRange {
        min
        max
      }
      memoryCostKib
      memoryCostKibRange {
        min
        max
      }
      parallelism
      parallelismRange {
        min
        max
      }
    }
    version
  }
  session {
    sessionLifetimeHours
    sessionLifetimeHoursRange {
      min
      max
    }
    elevatedAuthenticationLifetimeMinutes
    elevatedAuthenticationLifetimeMinutesRange {
      min
      max
    }
    recentAuthenticationLifetimeMinutes
    recentAuthenticationLifetimeMinutesRange {
      min
      max
    }
    loginLifetimeMinutes
    loginLifetimeMinutesRange {
      min
      max
    }
    version
  }
  email {
    delivery {
      enabled
      host
      port
      portRange {
        min
        max
      }
      security
      senderAddress
      senderName
      authentication {
        method
        username
        passwordSet
        tokenEndpoint
        clientId
        clientSecretSet
        grant
        refreshTokenSet
        scope
      }
      configured
      version
    }
    policy {
      signInCodeLifetimeMinutes
      signInCodeLifetimeMinutesRange {
        min
        max
      }
      passwordResetLifetimeMinutes
      passwordResetLifetimeMinutesRange {
        min
        max
      }
      registrationLifetimeMinutes
      registrationLifetimeMinutesRange {
        min
        max
      }
      emailVerificationLifetimeHours
      emailVerificationLifetimeHoursRange {
        min
        max
      }
      userInvitationLifetimeDays
      userInvitationLifetimeDaysRange {
        min
        max
      }
      resendIntervalSeconds
      resendIntervalSecondsRange {
        min
        max
      }
      loginMaxSends
      loginMaxSendsRange {
        min
        max
      }
      verificationMaxSends
      verificationMaxSendsRange {
        min
        max
      }
      verificationSendWindowHours
      verificationSendWindowHoursRange {
        min
        max
      }
      version
    }
    templates {
      kind
      variables
      previewScenarios
      customized
      version
      content {
        ...ConsoleLocalizedEmailTemplateFields
      }
      builtIn {
        ...ConsoleLocalizedEmailTemplateFields
      }
    }
  }
}
fragment ConsoleLocalizedEmailTemplateFields on LocalizedEmailTemplate {
  default {
    subject
    html
  }
  translations {
    locale
    content {
      subject
      html
    }
  }
}`) as unknown as TypedDocumentString<ConsoleInstanceSettingsQuery, ConsoleInstanceSettingsQueryVariables>;
export const ConsoleUpdateProtocolSettingsDocument = new TypedDocumentString(`
    mutation ConsoleUpdateProtocolSettings($input: UpdateProtocolSettingsInput!) {
  updateProtocolSettings(input: $input) {
    clientMutationId
    settings {
      ...ConsoleInstanceSettingsFields
    }
  }
}
    fragment ConsoleInstanceSettingsFields on InstanceSettings {
  general {
    issuer
    loginUrl
    consoleUrl
    initializedAt
  }
  protocol {
    oauthVersion
    requirePushedAuthorizationRequests
    pushedAuthorizationRequestLifetimeSeconds
    pushedAuthorizationRequestLifetimeRange {
      min
      max
    }
    deviceAuthorizationRequestLifetimeSeconds
    deviceAuthorizationRequestLifetimeRange {
      min
      max
    }
    deviceAuthorizationPollingIntervalSeconds
    deviceAuthorizationPollingIntervalRange {
      min
      max
    }
    dynamicRegistrationEnabled
    accessTokenLifetimeSeconds
    accessTokenLifetimeRange {
      min
      max
    }
    idTokenLifetimeSeconds
    idTokenLifetimeRange {
      min
      max
    }
    refreshTokenLifetimeDays
    refreshTokenLifetimeDaysRange {
      min
      max
    }
    authorizationCodeLifetimeSeconds
    authorizationCodeLifetimeRange {
      min
      max
    }
    version
  }
  authentication {
    breachedPasswordCheckEnabled
    identifierEnumerationAllowed
    emailSignInEnabled
    passwordResetEnabled
    registrationEnabled
    passwordMaxAgeDays
    passwordMaxAgeDaysRange {
      min
      max
    }
    passwordHistoryCount
    passwordHistoryCountRange {
      min
      max
    }
    passwordMinLength
    passwordMinLengthRange {
      min
      max
    }
    maxFailedAttempts
    maxFailedAttemptsRange {
      min
      max
    }
    lockoutDurationMinutes
    lockoutDurationMinutesRange {
      min
      max
    }
    passwordHashing {
      timeCost
      timeCostRange {
        min
        max
      }
      memoryCostKib
      memoryCostKibRange {
        min
        max
      }
      parallelism
      parallelismRange {
        min
        max
      }
    }
    version
  }
  session {
    sessionLifetimeHours
    sessionLifetimeHoursRange {
      min
      max
    }
    elevatedAuthenticationLifetimeMinutes
    elevatedAuthenticationLifetimeMinutesRange {
      min
      max
    }
    recentAuthenticationLifetimeMinutes
    recentAuthenticationLifetimeMinutesRange {
      min
      max
    }
    loginLifetimeMinutes
    loginLifetimeMinutesRange {
      min
      max
    }
    version
  }
  email {
    delivery {
      enabled
      host
      port
      portRange {
        min
        max
      }
      security
      senderAddress
      senderName
      authentication {
        method
        username
        passwordSet
        tokenEndpoint
        clientId
        clientSecretSet
        grant
        refreshTokenSet
        scope
      }
      configured
      version
    }
    policy {
      signInCodeLifetimeMinutes
      signInCodeLifetimeMinutesRange {
        min
        max
      }
      passwordResetLifetimeMinutes
      passwordResetLifetimeMinutesRange {
        min
        max
      }
      registrationLifetimeMinutes
      registrationLifetimeMinutesRange {
        min
        max
      }
      emailVerificationLifetimeHours
      emailVerificationLifetimeHoursRange {
        min
        max
      }
      userInvitationLifetimeDays
      userInvitationLifetimeDaysRange {
        min
        max
      }
      resendIntervalSeconds
      resendIntervalSecondsRange {
        min
        max
      }
      loginMaxSends
      loginMaxSendsRange {
        min
        max
      }
      verificationMaxSends
      verificationMaxSendsRange {
        min
        max
      }
      verificationSendWindowHours
      verificationSendWindowHoursRange {
        min
        max
      }
      version
    }
    templates {
      kind
      variables
      previewScenarios
      customized
      version
      content {
        ...ConsoleLocalizedEmailTemplateFields
      }
      builtIn {
        ...ConsoleLocalizedEmailTemplateFields
      }
    }
  }
}
fragment ConsoleLocalizedEmailTemplateFields on LocalizedEmailTemplate {
  default {
    subject
    html
  }
  translations {
    locale
    content {
      subject
      html
    }
  }
}`) as unknown as TypedDocumentString<ConsoleUpdateProtocolSettingsMutation, ConsoleUpdateProtocolSettingsMutationVariables>;
export const ConsoleUpdateAuthenticationSettingsDocument = new TypedDocumentString(`
    mutation ConsoleUpdateAuthenticationSettings($input: UpdateAuthenticationSettingsInput!) {
  updateAuthenticationSettings(input: $input) {
    clientMutationId
    settings {
      ...ConsoleInstanceSettingsFields
    }
  }
}
    fragment ConsoleInstanceSettingsFields on InstanceSettings {
  general {
    issuer
    loginUrl
    consoleUrl
    initializedAt
  }
  protocol {
    oauthVersion
    requirePushedAuthorizationRequests
    pushedAuthorizationRequestLifetimeSeconds
    pushedAuthorizationRequestLifetimeRange {
      min
      max
    }
    deviceAuthorizationRequestLifetimeSeconds
    deviceAuthorizationRequestLifetimeRange {
      min
      max
    }
    deviceAuthorizationPollingIntervalSeconds
    deviceAuthorizationPollingIntervalRange {
      min
      max
    }
    dynamicRegistrationEnabled
    accessTokenLifetimeSeconds
    accessTokenLifetimeRange {
      min
      max
    }
    idTokenLifetimeSeconds
    idTokenLifetimeRange {
      min
      max
    }
    refreshTokenLifetimeDays
    refreshTokenLifetimeDaysRange {
      min
      max
    }
    authorizationCodeLifetimeSeconds
    authorizationCodeLifetimeRange {
      min
      max
    }
    version
  }
  authentication {
    breachedPasswordCheckEnabled
    identifierEnumerationAllowed
    emailSignInEnabled
    passwordResetEnabled
    registrationEnabled
    passwordMaxAgeDays
    passwordMaxAgeDaysRange {
      min
      max
    }
    passwordHistoryCount
    passwordHistoryCountRange {
      min
      max
    }
    passwordMinLength
    passwordMinLengthRange {
      min
      max
    }
    maxFailedAttempts
    maxFailedAttemptsRange {
      min
      max
    }
    lockoutDurationMinutes
    lockoutDurationMinutesRange {
      min
      max
    }
    passwordHashing {
      timeCost
      timeCostRange {
        min
        max
      }
      memoryCostKib
      memoryCostKibRange {
        min
        max
      }
      parallelism
      parallelismRange {
        min
        max
      }
    }
    version
  }
  session {
    sessionLifetimeHours
    sessionLifetimeHoursRange {
      min
      max
    }
    elevatedAuthenticationLifetimeMinutes
    elevatedAuthenticationLifetimeMinutesRange {
      min
      max
    }
    recentAuthenticationLifetimeMinutes
    recentAuthenticationLifetimeMinutesRange {
      min
      max
    }
    loginLifetimeMinutes
    loginLifetimeMinutesRange {
      min
      max
    }
    version
  }
  email {
    delivery {
      enabled
      host
      port
      portRange {
        min
        max
      }
      security
      senderAddress
      senderName
      authentication {
        method
        username
        passwordSet
        tokenEndpoint
        clientId
        clientSecretSet
        grant
        refreshTokenSet
        scope
      }
      configured
      version
    }
    policy {
      signInCodeLifetimeMinutes
      signInCodeLifetimeMinutesRange {
        min
        max
      }
      passwordResetLifetimeMinutes
      passwordResetLifetimeMinutesRange {
        min
        max
      }
      registrationLifetimeMinutes
      registrationLifetimeMinutesRange {
        min
        max
      }
      emailVerificationLifetimeHours
      emailVerificationLifetimeHoursRange {
        min
        max
      }
      userInvitationLifetimeDays
      userInvitationLifetimeDaysRange {
        min
        max
      }
      resendIntervalSeconds
      resendIntervalSecondsRange {
        min
        max
      }
      loginMaxSends
      loginMaxSendsRange {
        min
        max
      }
      verificationMaxSends
      verificationMaxSendsRange {
        min
        max
      }
      verificationSendWindowHours
      verificationSendWindowHoursRange {
        min
        max
      }
      version
    }
    templates {
      kind
      variables
      previewScenarios
      customized
      version
      content {
        ...ConsoleLocalizedEmailTemplateFields
      }
      builtIn {
        ...ConsoleLocalizedEmailTemplateFields
      }
    }
  }
}
fragment ConsoleLocalizedEmailTemplateFields on LocalizedEmailTemplate {
  default {
    subject
    html
  }
  translations {
    locale
    content {
      subject
      html
    }
  }
}`) as unknown as TypedDocumentString<ConsoleUpdateAuthenticationSettingsMutation, ConsoleUpdateAuthenticationSettingsMutationVariables>;
export const ConsoleUpdateSessionSettingsDocument = new TypedDocumentString(`
    mutation ConsoleUpdateSessionSettings($input: UpdateSessionSettingsInput!) {
  updateSessionSettings(input: $input) {
    clientMutationId
    settings {
      ...ConsoleInstanceSettingsFields
    }
  }
}
    fragment ConsoleInstanceSettingsFields on InstanceSettings {
  general {
    issuer
    loginUrl
    consoleUrl
    initializedAt
  }
  protocol {
    oauthVersion
    requirePushedAuthorizationRequests
    pushedAuthorizationRequestLifetimeSeconds
    pushedAuthorizationRequestLifetimeRange {
      min
      max
    }
    deviceAuthorizationRequestLifetimeSeconds
    deviceAuthorizationRequestLifetimeRange {
      min
      max
    }
    deviceAuthorizationPollingIntervalSeconds
    deviceAuthorizationPollingIntervalRange {
      min
      max
    }
    dynamicRegistrationEnabled
    accessTokenLifetimeSeconds
    accessTokenLifetimeRange {
      min
      max
    }
    idTokenLifetimeSeconds
    idTokenLifetimeRange {
      min
      max
    }
    refreshTokenLifetimeDays
    refreshTokenLifetimeDaysRange {
      min
      max
    }
    authorizationCodeLifetimeSeconds
    authorizationCodeLifetimeRange {
      min
      max
    }
    version
  }
  authentication {
    breachedPasswordCheckEnabled
    identifierEnumerationAllowed
    emailSignInEnabled
    passwordResetEnabled
    registrationEnabled
    passwordMaxAgeDays
    passwordMaxAgeDaysRange {
      min
      max
    }
    passwordHistoryCount
    passwordHistoryCountRange {
      min
      max
    }
    passwordMinLength
    passwordMinLengthRange {
      min
      max
    }
    maxFailedAttempts
    maxFailedAttemptsRange {
      min
      max
    }
    lockoutDurationMinutes
    lockoutDurationMinutesRange {
      min
      max
    }
    passwordHashing {
      timeCost
      timeCostRange {
        min
        max
      }
      memoryCostKib
      memoryCostKibRange {
        min
        max
      }
      parallelism
      parallelismRange {
        min
        max
      }
    }
    version
  }
  session {
    sessionLifetimeHours
    sessionLifetimeHoursRange {
      min
      max
    }
    elevatedAuthenticationLifetimeMinutes
    elevatedAuthenticationLifetimeMinutesRange {
      min
      max
    }
    recentAuthenticationLifetimeMinutes
    recentAuthenticationLifetimeMinutesRange {
      min
      max
    }
    loginLifetimeMinutes
    loginLifetimeMinutesRange {
      min
      max
    }
    version
  }
  email {
    delivery {
      enabled
      host
      port
      portRange {
        min
        max
      }
      security
      senderAddress
      senderName
      authentication {
        method
        username
        passwordSet
        tokenEndpoint
        clientId
        clientSecretSet
        grant
        refreshTokenSet
        scope
      }
      configured
      version
    }
    policy {
      signInCodeLifetimeMinutes
      signInCodeLifetimeMinutesRange {
        min
        max
      }
      passwordResetLifetimeMinutes
      passwordResetLifetimeMinutesRange {
        min
        max
      }
      registrationLifetimeMinutes
      registrationLifetimeMinutesRange {
        min
        max
      }
      emailVerificationLifetimeHours
      emailVerificationLifetimeHoursRange {
        min
        max
      }
      userInvitationLifetimeDays
      userInvitationLifetimeDaysRange {
        min
        max
      }
      resendIntervalSeconds
      resendIntervalSecondsRange {
        min
        max
      }
      loginMaxSends
      loginMaxSendsRange {
        min
        max
      }
      verificationMaxSends
      verificationMaxSendsRange {
        min
        max
      }
      verificationSendWindowHours
      verificationSendWindowHoursRange {
        min
        max
      }
      version
    }
    templates {
      kind
      variables
      previewScenarios
      customized
      version
      content {
        ...ConsoleLocalizedEmailTemplateFields
      }
      builtIn {
        ...ConsoleLocalizedEmailTemplateFields
      }
    }
  }
}
fragment ConsoleLocalizedEmailTemplateFields on LocalizedEmailTemplate {
  default {
    subject
    html
  }
  translations {
    locale
    content {
      subject
      html
    }
  }
}`) as unknown as TypedDocumentString<ConsoleUpdateSessionSettingsMutation, ConsoleUpdateSessionSettingsMutationVariables>;
export const ConsoleUserRolesDocument = new TypedDocumentString(`
    query ConsoleUserRoles($userId: ID!, $source: AuthorizationSource, $enabled: Boolean, $orderBy: UserRoleOrder, $first: Int, $after: String, $last: Int, $before: String) {
  user(id: $userId) {
    id
    roles(
      source: $source
      enabled: $enabled
      orderBy: $orderBy
      first: $first
      after: $after
      last: $last
      before: $before
    ) {
      userVersion
      pageInfo {
        hasNextPage
        hasPreviousPage
        startCursor
        endCursor
      }
      edges {
        cursor
        source
        groupId
        enabled
        revokedAt
        reason
        createdAt
        updatedAt
        node {
          id
          name
          description
          enabled
          names {
            locale
            value
          }
        }
      }
    }
  }
}
    `) as unknown as TypedDocumentString<ConsoleUserRolesQuery, ConsoleUserRolesQueryVariables>;
export const ConsoleUserRoleVersionDocument = new TypedDocumentString(`
    query ConsoleUserRoleVersion($userId: ID!) {
  user(id: $userId) {
    id
    roles(source: DIRECT, first: 1) {
      userVersion
    }
  }
}
    `) as unknown as TypedDocumentString<ConsoleUserRoleVersionQuery, ConsoleUserRoleVersionQueryVariables>;
export const ConsoleUserPermissionsDocument = new TypedDocumentString(`
    query ConsoleUserPermissions($userId: ID!, $resourceId: ID!, $source: AuthorizationSource, $orderBy: EffectivePermissionOrder, $first: Int, $after: String, $last: Int, $before: String) {
  user(id: $userId) {
    id
    effectivePermissions(
      resourceId: $resourceId
      source: $source
      orderBy: $orderBy
      first: $first
      after: $after
      last: $last
      before: $before
    ) {
      totalCount
      userVersion
      pageInfo {
        hasNextPage
        hasPreviousPage
        startCursor
        endCursor
      }
      edges {
        cursor
        node {
          permissionId
          resourceId
          code
          sources {
            roleId
          }
          groupSources {
            groupId
            roleId
          }
        }
      }
    }
  }
}
    `) as unknown as TypedDocumentString<ConsoleUserPermissionsQuery, ConsoleUserPermissionsQueryVariables>;
export const ConsoleAssignUserRolesDocument = new TypedDocumentString(`
    mutation ConsoleAssignUserRoles($input: AssignUserRolesInput!) {
  assignUserRoles(input: $input) {
    userId
    userVersion
    createdCount
    revokedCount
  }
}
    `) as unknown as TypedDocumentString<ConsoleAssignUserRolesMutation, ConsoleAssignUserRolesMutationVariables>;
export const ConsoleRevokeUserRolesDocument = new TypedDocumentString(`
    mutation ConsoleRevokeUserRoles($input: RevokeUserRolesInput!) {
  revokeUserRoles(input: $input) {
    userId
    userVersion
    createdCount
    revokedCount
  }
}
    `) as unknown as TypedDocumentString<ConsoleRevokeUserRolesMutation, ConsoleRevokeUserRolesMutationVariables>;
export const ConsoleAuthorizationLabelsDocument = new TypedDocumentString(`
    query ConsoleAuthorizationLabels($ids: [ID!]!) {
  nodes(ids: $ids) {
    id
    __typename
    ... on Scope {
      code
      name
      description
      names {
        locale
        value
      }
      descriptions {
        locale
        value
      }
    }
    ... on Group {
      name
      names {
        locale
        value
      }
    }
    ... on Role {
      name
      description
      names {
        locale
        value
      }
    }
  }
}
    `) as unknown as TypedDocumentString<ConsoleAuthorizationLabelsQuery, ConsoleAuthorizationLabelsQueryVariables>;
export const ConsoleGroupsDocument = new TypedDocumentString(`
    query ConsoleGroups($filter: GroupFilter, $orderBy: GroupOrder, $first: Int, $after: String, $last: Int, $before: String) {
  groups(
    filter: $filter
    orderBy: $orderBy
    first: $first
    after: $after
    last: $last
    before: $before
  ) {
    totalCount
    pageInfo {
      hasNextPage
      hasPreviousPage
      startCursor
      endCursor
    }
    edges {
      cursor
      node {
        id
        builtIn
        name
        description
        names {
          locale
          value
        }
        descriptions {
          locale
          value
        }
        enabled
        version
        createdAt
        updatedAt
      }
    }
  }
}
    `) as unknown as TypedDocumentString<ConsoleGroupsQuery, ConsoleGroupsQueryVariables>;
export const ConsoleGroupDocument = new TypedDocumentString(`
    query ConsoleGroup($id: ID!) {
  group(id: $id) {
    id
    builtIn
    name
    description
    names {
      locale
      value
    }
    descriptions {
      locale
      value
    }
    enabled
    version
    createdAt
    updatedAt
  }
}
    `) as unknown as TypedDocumentString<ConsoleGroupQuery, ConsoleGroupQueryVariables>;
export const ConsoleGroupMembersDocument = new TypedDocumentString(`
    query ConsoleGroupMembers($groupId: ID!, $filter: GroupMembershipFilter, $orderBy: GroupMembershipOrder, $first: Int, $after: String, $last: Int, $before: String) {
  group(id: $groupId) {
    id
    builtIn
    name
    description
    names {
      locale
      value
    }
    version
    members(
      filter: $filter
      orderBy: $orderBy
      first: $first
      after: $after
      last: $last
      before: $before
    ) {
      pageInfo {
        hasNextPage
        hasPreviousPage
        startCursor
        endCursor
      }
      edges {
        cursor
        enabled
        revokedAt
        createdAt
        updatedAt
        grantedBy {
          id
          username
        }
        node {
          id
          username
          email
          enabled
          locked
        }
      }
    }
  }
}
    `) as unknown as TypedDocumentString<ConsoleGroupMembersQuery, ConsoleGroupMembersQueryVariables>;
export const ConsoleGroupRolesDocument = new TypedDocumentString(`
    query ConsoleGroupRoles($groupId: ID!, $filter: GroupRoleFilter, $orderBy: GroupRoleOrder, $first: Int, $after: String, $last: Int, $before: String) {
  group(id: $groupId) {
    id
    builtIn
    name
    description
    names {
      locale
      value
    }
    version
    roles(
      filter: $filter
      orderBy: $orderBy
      first: $first
      after: $after
      last: $last
      before: $before
    ) {
      pageInfo {
        hasNextPage
        hasPreviousPage
        startCursor
        endCursor
      }
      edges {
        cursor
        enabled
        revokedAt
        createdAt
        updatedAt
        node {
          id
          name
          builtIn
          description
          names {
            locale
            value
          }
          descriptions {
            locale
            value
          }
          enabled
          version
        }
      }
    }
  }
}
    `) as unknown as TypedDocumentString<ConsoleGroupRolesQuery, ConsoleGroupRolesQueryVariables>;
export const ConsoleGroupRoleIdsDocument = new TypedDocumentString(`
    query ConsoleGroupRoleIds($groupId: ID!, $first: Int!, $after: String) {
  group(id: $groupId) {
    id
    version
    roles(
      filter: { enabled: true }
      orderBy: ROLE_NAME_ASC
      first: $first
      after: $after
    ) {
      pageInfo {
        hasNextPage
        endCursor
      }
      edges {
        enabled
        revokedAt
        node {
          id
        }
      }
    }
  }
}
    `) as unknown as TypedDocumentString<ConsoleGroupRoleIdsQuery, ConsoleGroupRoleIdsQueryVariables>;
export const ConsoleCreateGroupDocument = new TypedDocumentString(`
    mutation ConsoleCreateGroup($input: CreateGroupInput!) {
  createGroup(input: $input) {
    groupId
    version
  }
}
    `) as unknown as TypedDocumentString<ConsoleCreateGroupMutation, ConsoleCreateGroupMutationVariables>;
export const ConsoleUpdateGroupDocument = new TypedDocumentString(`
    mutation ConsoleUpdateGroup($input: UpdateGroupInput!) {
  updateGroup(input: $input) {
    groupId
    version
  }
}
    `) as unknown as TypedDocumentString<ConsoleUpdateGroupMutation, ConsoleUpdateGroupMutationVariables>;
export const ConsoleAddGroupMemberDocument = new TypedDocumentString(`
    mutation ConsoleAddGroupMember($input: AddGroupMemberInput!) {
  addGroupMember(input: $input) {
    groupId
    userId
    groupVersion
  }
}
    `) as unknown as TypedDocumentString<ConsoleAddGroupMemberMutation, ConsoleAddGroupMemberMutationVariables>;
export const ConsoleRemoveGroupMemberDocument = new TypedDocumentString(`
    mutation ConsoleRemoveGroupMember($input: RemoveGroupMemberInput!) {
  removeGroupMember(input: $input) {
    groupId
    userId
    groupVersion
  }
}
    `) as unknown as TypedDocumentString<ConsoleRemoveGroupMemberMutation, ConsoleRemoveGroupMemberMutationVariables>;
export const ConsoleSetGroupRolesDocument = new TypedDocumentString(`
    mutation ConsoleSetGroupRoles($input: SetGroupRolesInput!) {
  setGroupRoles(input: $input) {
    groupId
    groupVersion
    roleIds
    addedCount
    removedCount
  }
}
    `) as unknown as TypedDocumentString<ConsoleSetGroupRolesMutation, ConsoleSetGroupRolesMutationVariables>;
export const ConsoleSetGroupEnabledDocument = new TypedDocumentString(`
    mutation ConsoleSetGroupEnabled($input: SetGroupEnabledInput!) {
  setGroupEnabled(input: $input) {
    groupId
    version
  }
}
    `) as unknown as TypedDocumentString<ConsoleSetGroupEnabledMutation, ConsoleSetGroupEnabledMutationVariables>;
export const ConsoleDeleteGroupDocument = new TypedDocumentString(`
    mutation ConsoleDeleteGroup($input: GroupStateInput!) {
  deleteGroup(input: $input) {
    groupId
    deleted
  }
}
    `) as unknown as TypedDocumentString<ConsoleDeleteGroupMutation, ConsoleDeleteGroupMutationVariables>;
export const ConsolePermissionOptionsDocument = new TypedDocumentString(`
    query ConsolePermissionOptions($filter: ScopeFilter, $orderBy: ScopeOrder, $first: Int, $after: String, $last: Int, $before: String) {
  permissions: scopes(
    filter: $filter
    orderBy: $orderBy
    first: $first
    after: $after
    last: $last
    before: $before
  ) {
    totalCount
    pageInfo {
      hasNextPage
      hasPreviousPage
      startCursor
      endCursor
    }
    edges {
      cursor
      node {
        id
        resourceId
        code
        name
        description
        builtIn
        enabled
        names {
          locale
          value
        }
        descriptions {
          locale
          value
        }
      }
    }
  }
}
    `) as unknown as TypedDocumentString<ConsolePermissionOptionsQuery, ConsolePermissionOptionsQueryVariables>;
export const ConsoleRoleGroupsDocument = new TypedDocumentString(`
    query ConsoleRoleGroups($roleId: ID!, $filter: GroupFilter, $orderBy: GroupOrder, $first: Int, $after: String, $last: Int, $before: String) {
  role(id: $roleId) {
    id
    groups(
      filter: $filter
      orderBy: $orderBy
      first: $first
      after: $after
      last: $last
      before: $before
    ) {
      pageInfo {
        hasNextPage
        hasPreviousPage
        startCursor
        endCursor
      }
      edges {
        cursor
        node {
          id
          builtIn
          name
          description
          names {
            locale
            value
          }
          descriptions {
            locale
            value
          }
          enabled
          updatedAt
        }
      }
    }
  }
}
    `) as unknown as TypedDocumentString<ConsoleRoleGroupsQuery, ConsoleRoleGroupsQueryVariables>;
export const ConsoleRolesDocument = new TypedDocumentString(`
    query ConsoleRoles($filter: RoleFilter, $orderBy: RoleOrder, $first: Int, $after: String, $last: Int, $before: String) {
  roles(
    filter: $filter
    orderBy: $orderBy
    first: $first
    after: $after
    last: $last
    before: $before
  ) {
    totalCount
    pageInfo {
      hasNextPage
      hasPreviousPage
      startCursor
      endCursor
    }
    edges {
      cursor
      node {
        id
        name
        description
        builtIn
        names {
          locale
          value
        }
        descriptions {
          locale
          value
        }
        enabled
        version
        createdAt
        updatedAt
      }
    }
  }
}
    `) as unknown as TypedDocumentString<ConsoleRolesQuery, ConsoleRolesQueryVariables>;
export const ConsoleRoleDocument = new TypedDocumentString(`
    query ConsoleRole($id: ID!) {
  role(id: $id) {
    id
    name
    description
    builtIn
    names {
      locale
      value
    }
    descriptions {
      locale
      value
    }
    enabled
    version
    createdAt
    updatedAt
  }
}
    `) as unknown as TypedDocumentString<ConsoleRoleQuery, ConsoleRoleQueryVariables>;
export const ConsoleCreateRoleDocument = new TypedDocumentString(`
    mutation ConsoleCreateRole($input: CreateRoleInput!) {
  createRole(input: $input) {
    roleId
    version
  }
}
    `) as unknown as TypedDocumentString<ConsoleCreateRoleMutation, ConsoleCreateRoleMutationVariables>;
export const ConsoleUpdateRoleDocument = new TypedDocumentString(`
    mutation ConsoleUpdateRole($input: UpdateRoleInput!) {
  updateRole(input: $input) {
    roleId
    version
  }
}
    `) as unknown as TypedDocumentString<ConsoleUpdateRoleMutation, ConsoleUpdateRoleMutationVariables>;
export const ConsoleEnableRoleDocument = new TypedDocumentString(`
    mutation ConsoleEnableRole($input: RoleStateInput!) {
  enableRole(input: $input) {
    roleId
    version
  }
}
    `) as unknown as TypedDocumentString<ConsoleEnableRoleMutation, ConsoleEnableRoleMutationVariables>;
export const ConsoleDisableRoleDocument = new TypedDocumentString(`
    mutation ConsoleDisableRole($input: RoleStateInput!) {
  disableRole(input: $input) {
    roleId
    version
  }
}
    `) as unknown as TypedDocumentString<ConsoleDisableRoleMutation, ConsoleDisableRoleMutationVariables>;
export const ConsoleSetRolePermissionsDocument = new TypedDocumentString(`
    mutation ConsoleSetRolePermissions($input: SetRolePermissionsInput!) {
  setRolePermissions(input: $input) {
    roleId
    version
  }
}
    `) as unknown as TypedDocumentString<ConsoleSetRolePermissionsMutation, ConsoleSetRolePermissionsMutationVariables>;
export const ConsoleRoleUsersDocument = new TypedDocumentString(`
    query ConsoleRoleUsers($roleId: ID!, $enabled: Boolean, $orderBy: UserRoleOrder, $first: Int, $after: String, $last: Int, $before: String) {
  role(id: $roleId) {
    id
    users(
      enabled: $enabled
      orderBy: $orderBy
      first: $first
      after: $after
      last: $last
      before: $before
    ) {
      pageInfo {
        hasNextPage
        hasPreviousPage
        startCursor
        endCursor
      }
      edges {
        cursor
        enabled
        revokedAt
        reason
        createdAt
        updatedAt
        node {
          id
          username
          email
          enabled
          locked
          version
        }
      }
    }
  }
}
    `) as unknown as TypedDocumentString<ConsoleRoleUsersQuery, ConsoleRoleUsersQueryVariables>;
export const ConsoleResourceOptionsDocument = new TypedDocumentString(`
    query ConsoleResourceOptions($filter: ResourceFilter, $first: Int, $after: String) {
  resources(filter: $filter, orderBy: NAME_ASC, first: $first, after: $after) {
    pageInfo {
      hasNextPage
      hasPreviousPage
      startCursor
      endCursor
    }
    edges {
      cursor
      node {
        id
        uri
        name
        enabled
      }
    }
  }
}
    `) as unknown as TypedDocumentString<ConsoleResourceOptionsQuery, ConsoleResourceOptionsQueryVariables>;
export const ConsoleUsersDocument = new TypedDocumentString(`
    query ConsoleUsers($filter: UserFilter, $orderBy: UserOrder, $first: Int, $after: String, $last: Int, $before: String) {
  users(
    filter: $filter
    orderBy: $orderBy
    first: $first
    after: $after
    last: $last
    before: $before
  ) {
    totalCount
    pageInfo {
      hasNextPage
      hasPreviousPage
      startCursor
      endCursor
    }
    edges {
      cursor
      node {
        id
        username
        email
        emailVerified
        enabled
        locked
        lockedUntil
        failedAttempts
        invitation {
          expiresAt
          delivery {
            status
          }
        }
        version
        createdAt
        updatedAt
      }
    }
  }
}
    `) as unknown as TypedDocumentString<ConsoleUsersQuery, ConsoleUsersQueryVariables>;
export const ConsoleUserDocument = new TypedDocumentString(`
    query ConsoleUser($id: ID!) {
  user(id: $id) {
    id
    username
    email
    emailVerified
    enabled
    locked
    lockedUntil
    failedAttempts
    requiredActions
    invitation {
      sentAt
      expiresAt
      delivery {
        status
        failure
        updatedAt
      }
    }
    authenticationMethods {
      password
      authenticatorApp
      recoveryCodes
      passkey
    }
    version
    givenName
    familyName
    middleName
    nickname
    profile
    picture
    website
    birthdate
    locale
    theme
    createdAt
    updatedAt
  }
}
    `) as unknown as TypedDocumentString<ConsoleUserQuery, ConsoleUserQueryVariables>;
export const ConsoleUserInvitationsAvailableDocument = new TypedDocumentString(`
    query ConsoleUserInvitationsAvailable {
  userInvitationsAvailable
}
    `) as unknown as TypedDocumentString<ConsoleUserInvitationsAvailableQuery, ConsoleUserInvitationsAvailableQueryVariables>;
export const ConsoleCreateUserDocument = new TypedDocumentString(`
    mutation ConsoleCreateUser($input: CreateUserInput!) {
  createUser(input: $input) {
    userId
    version
  }
}
    `) as unknown as TypedDocumentString<ConsoleCreateUserMutation, ConsoleCreateUserMutationVariables>;
export const ConsoleSendUserInvitationDocument = new TypedDocumentString(`
    mutation ConsoleSendUserInvitation($input: SendUserInvitationInput!) {
  sendUserInvitation(input: $input) {
    userId
    invitation {
      sentAt
      expiresAt
      delivery {
        status
        failure
        updatedAt
      }
    }
  }
}
    `) as unknown as TypedDocumentString<ConsoleSendUserInvitationMutation, ConsoleSendUserInvitationMutationVariables>;
export const ConsoleUpdateUserDocument = new TypedDocumentString(`
    mutation ConsoleUpdateUser($input: UpdateUserInput!) {
  updateUser(input: $input) {
    userId
    version
  }
}
    `) as unknown as TypedDocumentString<ConsoleUpdateUserMutation, ConsoleUpdateUserMutationVariables>;
export const ConsoleEnableUserDocument = new TypedDocumentString(`
    mutation ConsoleEnableUser($input: UserStateInput!) {
  enableUser(input: $input) {
    userId
    version
  }
}
    `) as unknown as TypedDocumentString<ConsoleEnableUserMutation, ConsoleEnableUserMutationVariables>;
export const ConsoleDisableUserDocument = new TypedDocumentString(`
    mutation ConsoleDisableUser($input: UserStateInput!) {
  disableUser(input: $input) {
    userId
    version
  }
}
    `) as unknown as TypedDocumentString<ConsoleDisableUserMutation, ConsoleDisableUserMutationVariables>;
export const ConsoleUnlockUserDocument = new TypedDocumentString(`
    mutation ConsoleUnlockUser($input: UnlockUserInput!) {
  unlockUser(input: $input) {
    userId
    version
  }
}
    `) as unknown as TypedDocumentString<ConsoleUnlockUserMutation, ConsoleUnlockUserMutationVariables>;
export const ConsoleUserGroupsDocument = new TypedDocumentString(`
    query ConsoleUserGroups($userId: ID!, $filter: GroupFilter, $orderBy: GroupOrder, $first: Int, $after: String, $last: Int, $before: String) {
  user(id: $userId) {
    id
    groups(
      filter: $filter
      orderBy: $orderBy
      first: $first
      after: $after
      last: $last
      before: $before
    ) {
      pageInfo {
        hasNextPage
        hasPreviousPage
        startCursor
        endCursor
      }
      edges {
        cursor
        node {
          id
          builtIn
          name
          description
          names {
            locale
            value
          }
          descriptions {
            locale
            value
          }
          enabled
          version
        }
      }
    }
  }
}
    `) as unknown as TypedDocumentString<ConsoleUserGroupsQuery, ConsoleUserGroupsQueryVariables>;
export const ConsoleUserSessionsDocument = new TypedDocumentString(`
    query ConsoleUserSessions($userId: ID!, $first: Int, $after: String, $last: Int, $before: String) {
  user(id: $userId) {
    id
    sessions(first: $first, after: $after, last: $last, before: $before) {
      pageInfo {
        hasPreviousPage
        hasNextPage
        startCursor
        endCursor
      }
      edges {
        cursor
        node {
          id
          deviceName
          deviceType
          osName
          osVersion
          browserName
          browserVersion
          ipAddress
          lastActiveAt
          createdAt
        }
      }
    }
  }
}
    `) as unknown as TypedDocumentString<ConsoleUserSessionsQuery, ConsoleUserSessionsQueryVariables>;
export const ConsoleResetUserPasswordDocument = new TypedDocumentString(`
    mutation ConsoleResetUserPassword($input: UserStateInput!) {
  resetUserPassword(input: $input) {
    userId
    version
    temporaryPassword
  }
}
    `) as unknown as TypedDocumentString<ConsoleResetUserPasswordMutation, ConsoleResetUserPasswordMutationVariables>;
export const ConsoleResetUserMfaDocument = new TypedDocumentString(`
    mutation ConsoleResetUserMfa($input: UserStateInput!) {
  resetUserMfa(input: $input) {
    userId
    version
  }
}
    `) as unknown as TypedDocumentString<ConsoleResetUserMfaMutation, ConsoleResetUserMfaMutationVariables>;
export const ConsoleRevokeUserSessionsDocument = new TypedDocumentString(`
    mutation ConsoleRevokeUserSessions($input: RevokeUserSessionsInput!) {
  revokeUserSessions(input: $input) {
    userId
    version
  }
}
    `) as unknown as TypedDocumentString<ConsoleRevokeUserSessionsMutation, ConsoleRevokeUserSessionsMutationVariables>;
export const ConsoleDeleteUserDocument = new TypedDocumentString(`
    mutation ConsoleDeleteUser($input: UserStateInput!) {
  deleteUser(input: $input) {
    deletedUserId
  }
}
    `) as unknown as TypedDocumentString<ConsoleDeleteUserMutation, ConsoleDeleteUserMutationVariables>;