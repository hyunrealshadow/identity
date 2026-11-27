import type {
  ConsoleInstanceSettingsQuery,
  UpdateAuthenticationSettingsInput,
  UpdateProtocolSettingsInput,
  UpdateSessionSettingsInput,
} from '#/generated/graphql'
import type { MessageKey } from '#/lib/i18n'

export type InstanceSettings = NonNullable<ConsoleInstanceSettingsQuery['instanceSettings']>
export type ProtocolSettings = InstanceSettings['protocol']
export type AuthenticationSettings = InstanceSettings['authentication']
export type SessionSettings = InstanceSettings['session']

export interface SettingRange {
  min: number
  max: number
}

export interface FieldError {
  key: MessageKey
  values?: Record<string, number>
}

/** A whole number within `range`, or the reason it is not. */
export function parseWholeNumber(
  raw: string,
  range: SettingRange,
): { value: number } | { error: FieldError } {
  const trimmed = raw.trim()
  if (!/^\d+$/u.test(trimmed)) return { error: { key: 'settingsWholeNumberRequired' } }
  const value = Number(trimmed)
  if (!Number.isSafeInteger(value) || value < range.min || value > range.max) {
    return {
      error: { key: 'settingsOutOfRange', values: { min: range.min, max: range.max } },
    }
  }
  return { value }
}

export interface ProtocolDraft {
  oauthVersion: ProtocolSettings['oauthVersion']
  requirePushedAuthorizationRequests: boolean
  pushedAuthorizationRequestLifetimeSeconds: string
  deviceAuthorizationRequestLifetimeSeconds: string
  deviceAuthorizationPollingIntervalSeconds: string
  dynamicRegistrationEnabled: boolean
  accessTokenLifetimeSeconds: string
  idTokenLifetimeSeconds: string
  refreshTokenLifetimeDays: string
  authorizationCodeLifetimeSeconds: string
}

export type ProtocolNumberField =
  | 'pushedAuthorizationRequestLifetimeSeconds'
  | 'deviceAuthorizationRequestLifetimeSeconds'
  | 'deviceAuthorizationPollingIntervalSeconds'
  | 'accessTokenLifetimeSeconds'
  | 'idTokenLifetimeSeconds'
  | 'refreshTokenLifetimeDays'
  | 'authorizationCodeLifetimeSeconds'

export function protocolDraft(settings: ProtocolSettings): ProtocolDraft {
  return {
    oauthVersion: settings.oauthVersion,
    requirePushedAuthorizationRequests: settings.requirePushedAuthorizationRequests,
    pushedAuthorizationRequestLifetimeSeconds: String(
      settings.pushedAuthorizationRequestLifetimeSeconds,
    ),
    deviceAuthorizationRequestLifetimeSeconds: String(
      settings.deviceAuthorizationRequestLifetimeSeconds,
    ),
    deviceAuthorizationPollingIntervalSeconds: String(
      settings.deviceAuthorizationPollingIntervalSeconds,
    ),
    dynamicRegistrationEnabled: settings.dynamicRegistrationEnabled,
    accessTokenLifetimeSeconds: String(settings.accessTokenLifetimeSeconds),
    idTokenLifetimeSeconds: String(settings.idTokenLifetimeSeconds),
    refreshTokenLifetimeDays: String(settings.refreshTokenLifetimeDays),
    authorizationCodeLifetimeSeconds: String(settings.authorizationCodeLifetimeSeconds),
  }
}

const protocolRanges: Record<ProtocolNumberField, (settings: ProtocolSettings) => SettingRange> = {
  pushedAuthorizationRequestLifetimeSeconds: (settings) =>
    settings.pushedAuthorizationRequestLifetimeRange,
  deviceAuthorizationRequestLifetimeSeconds: (settings) =>
    settings.deviceAuthorizationRequestLifetimeRange,
  deviceAuthorizationPollingIntervalSeconds: (settings) =>
    settings.deviceAuthorizationPollingIntervalRange,
  accessTokenLifetimeSeconds: (settings) => settings.accessTokenLifetimeRange,
  idTokenLifetimeSeconds: (settings) => settings.idTokenLifetimeRange,
  refreshTokenLifetimeDays: (settings) => settings.refreshTokenLifetimeDaysRange,
  authorizationCodeLifetimeSeconds: (settings) => settings.authorizationCodeLifetimeRange,
}

export function protocolRange(settings: ProtocolSettings, field: ProtocolNumberField) {
  return protocolRanges[field](settings)
}

/** The mutation input for `draft`, or the fields that need attention. */
export function protocolInput(
  settings: ProtocolSettings,
  draft: ProtocolDraft,
):
  | { input: Omit<UpdateProtocolSettingsInput, 'clientMutationId'> }
  | { errors: Partial<Record<ProtocolNumberField, FieldError>> } {
  const errors: Partial<Record<ProtocolNumberField, FieldError>> = {}
  const values: Partial<Record<ProtocolNumberField, number>> = {}
  for (const field of Object.keys(protocolRanges) as ProtocolNumberField[]) {
    const parsed = parseWholeNumber(draft[field], protocolRange(settings, field))
    if ('error' in parsed) errors[field] = parsed.error
    else values[field] = parsed.value
  }
  if (Object.keys(errors).length) return { errors }
  return {
    input: {
      oauthVersion: draft.oauthVersion,
      requirePushedAuthorizationRequests: draft.requirePushedAuthorizationRequests,
      pushedAuthorizationRequestLifetimeSeconds: values.pushedAuthorizationRequestLifetimeSeconds!,
      deviceAuthorizationRequestLifetimeSeconds: values.deviceAuthorizationRequestLifetimeSeconds!,
      deviceAuthorizationPollingIntervalSeconds: values.deviceAuthorizationPollingIntervalSeconds!,
      dynamicRegistrationEnabled: draft.dynamicRegistrationEnabled,
      accessTokenLifetimeSeconds: values.accessTokenLifetimeSeconds!,
      idTokenLifetimeSeconds: values.idTokenLifetimeSeconds!,
      refreshTokenLifetimeDays: values.refreshTokenLifetimeDays!,
      authorizationCodeLifetimeSeconds: values.authorizationCodeLifetimeSeconds!,
      expectedVersion: settings.version,
    },
  }
}

export interface AuthenticationDraft {
  breachedPasswordCheckEnabled: boolean
  identifierEnumerationAllowed: boolean
  emailSignInEnabled: boolean
  passwordResetEnabled: boolean
  registrationEnabled: boolean
  passwordMaxAgeDays: string
  passwordHistoryCount: string
  passwordMinLength: string
  maxFailedAttempts: string
  lockoutDurationMinutes: string
  timeCost: string
  memoryCostKib: string
  parallelism: string
}

/** Numeric authentication settings, each checked against its server range. */
export type HashingField =
  | 'timeCost'
  | 'memoryCostKib'
  | 'parallelism'
  | 'passwordMaxAgeDays'
  | 'passwordHistoryCount'
  | 'passwordMinLength'
  | 'maxFailedAttempts'
  | 'lockoutDurationMinutes'

export function authenticationDraft(settings: AuthenticationSettings): AuthenticationDraft {
  return {
    breachedPasswordCheckEnabled: settings.breachedPasswordCheckEnabled,
    identifierEnumerationAllowed: settings.identifierEnumerationAllowed,
    emailSignInEnabled: settings.emailSignInEnabled,
    passwordResetEnabled: settings.passwordResetEnabled,
    registrationEnabled: settings.registrationEnabled,
    passwordMaxAgeDays: String(settings.passwordMaxAgeDays),
    passwordHistoryCount: String(settings.passwordHistoryCount),
    passwordMinLength: String(settings.passwordMinLength),
    maxFailedAttempts: String(settings.maxFailedAttempts),
    lockoutDurationMinutes: String(settings.lockoutDurationMinutes),
    timeCost: String(settings.passwordHashing.timeCost),
    memoryCostKib: String(settings.passwordHashing.memoryCostKib),
    parallelism: String(settings.passwordHashing.parallelism),
  }
}

export function hashingRange(settings: AuthenticationSettings, field: HashingField): SettingRange {
  if (field === 'passwordMaxAgeDays') return settings.passwordMaxAgeDaysRange
  if (field === 'passwordHistoryCount') return settings.passwordHistoryCountRange
  if (field === 'passwordMinLength') return settings.passwordMinLengthRange
  if (field === 'maxFailedAttempts') return settings.maxFailedAttemptsRange
  if (field === 'lockoutDurationMinutes') return settings.lockoutDurationMinutesRange
  const hashing = settings.passwordHashing
  return field === 'timeCost'
    ? hashing.timeCostRange
    : field === 'memoryCostKib'
      ? hashing.memoryCostKibRange
      : hashing.parallelismRange
}

export function authenticationInput(
  settings: AuthenticationSettings,
  draft: AuthenticationDraft,
):
  | { input: Omit<UpdateAuthenticationSettingsInput, 'clientMutationId'> }
  | { errors: Partial<Record<HashingField, FieldError>> } {
  const errors: Partial<Record<HashingField, FieldError>> = {}
  const values: Partial<Record<HashingField, number>> = {}
  for (const field of [
    'timeCost',
    'memoryCostKib',
    'parallelism',
    'passwordMaxAgeDays',
    'passwordHistoryCount',
    'passwordMinLength',
    'maxFailedAttempts',
    'lockoutDurationMinutes',
  ] as const) {
    const parsed = parseWholeNumber(draft[field], hashingRange(settings, field))
    if ('error' in parsed) errors[field] = parsed.error
    else values[field] = parsed.value
  }
  if (Object.keys(errors).length) return { errors }
  return {
    input: {
      breachedPasswordCheckEnabled: draft.breachedPasswordCheckEnabled,
      identifierEnumerationAllowed: draft.identifierEnumerationAllowed,
      emailSignInEnabled: draft.emailSignInEnabled,
      passwordResetEnabled: draft.passwordResetEnabled,
      registrationEnabled: draft.registrationEnabled,
      passwordMaxAgeDays: values.passwordMaxAgeDays!,
      passwordHistoryCount: values.passwordHistoryCount!,
      passwordMinLength: values.passwordMinLength!,
      maxFailedAttempts: values.maxFailedAttempts!,
      lockoutDurationMinutes: values.lockoutDurationMinutes!,
      passwordHashing: {
        timeCost: values.timeCost!,
        memoryCostKib: values.memoryCostKib!,
        parallelism: values.parallelism!,
      },
      expectedVersion: settings.version,
    },
  }
}

export interface SessionDraft {
  sessionLifetimeHours: string
  elevatedAuthenticationLifetimeMinutes: string
  recentAuthenticationLifetimeMinutes: string
  loginLifetimeMinutes: string
}

export type SessionNumberField =
  | 'sessionLifetimeHours'
  | 'elevatedAuthenticationLifetimeMinutes'
  | 'recentAuthenticationLifetimeMinutes'
  | 'loginLifetimeMinutes'

export function sessionDraft(settings: SessionSettings): SessionDraft {
  return {
    sessionLifetimeHours: String(settings.sessionLifetimeHours),
    elevatedAuthenticationLifetimeMinutes: String(settings.elevatedAuthenticationLifetimeMinutes),
    recentAuthenticationLifetimeMinutes: String(settings.recentAuthenticationLifetimeMinutes),
    loginLifetimeMinutes: String(settings.loginLifetimeMinutes),
  }
}

const sessionRanges: Record<SessionNumberField, (settings: SessionSettings) => SettingRange> = {
  sessionLifetimeHours: (settings) => settings.sessionLifetimeHoursRange,
  elevatedAuthenticationLifetimeMinutes: (settings) =>
    settings.elevatedAuthenticationLifetimeMinutesRange,
  recentAuthenticationLifetimeMinutes: (settings) =>
    settings.recentAuthenticationLifetimeMinutesRange,
  loginLifetimeMinutes: (settings) => settings.loginLifetimeMinutesRange,
}

export function sessionRange(settings: SessionSettings, field: SessionNumberField) {
  return sessionRanges[field](settings)
}

export function sessionInput(
  settings: SessionSettings,
  draft: SessionDraft,
):
  | { input: Omit<UpdateSessionSettingsInput, 'clientMutationId'> }
  | { errors: Partial<Record<SessionNumberField, FieldError>> } {
  const errors: Partial<Record<SessionNumberField, FieldError>> = {}
  const values: Partial<Record<SessionNumberField, number>> = {}
  for (const field of Object.keys(sessionRanges) as SessionNumberField[]) {
    const parsed = parseWholeNumber(draft[field], sessionRange(settings, field))
    if ('error' in parsed) errors[field] = parsed.error
    else values[field] = parsed.value
  }
  if (Object.keys(errors).length) return { errors }
  return {
    input: {
      sessionLifetimeHours: values.sessionLifetimeHours!,
      elevatedAuthenticationLifetimeMinutes: values.elevatedAuthenticationLifetimeMinutes!,
      recentAuthenticationLifetimeMinutes: values.recentAuthenticationLifetimeMinutes!,
      loginLifetimeMinutes: values.loginLifetimeMinutes!,
      expectedVersion: settings.version,
    },
  }
}
