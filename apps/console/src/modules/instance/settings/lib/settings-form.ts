import type {
  ConsoleInstanceSettingsQuery,
  UpdateAuthenticationSettingsInput,
  UpdateProtocolSettingsInput,
} from '#/generated/graphql'
import type { MessageKey } from '#/lib/i18n'

export type InstanceSettings = NonNullable<ConsoleInstanceSettingsQuery['instanceSettings']>
export type ProtocolSettings = InstanceSettings['protocol']
export type AuthenticationSettings = InstanceSettings['authentication']

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
}

export type ProtocolNumberField =
  | 'pushedAuthorizationRequestLifetimeSeconds'
  | 'deviceAuthorizationRequestLifetimeSeconds'
  | 'deviceAuthorizationPollingIntervalSeconds'

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
  }
}

const protocolRanges: Record<ProtocolNumberField, (settings: ProtocolSettings) => SettingRange> = {
  pushedAuthorizationRequestLifetimeSeconds: (settings) =>
    settings.pushedAuthorizationRequestLifetimeRange,
  deviceAuthorizationRequestLifetimeSeconds: (settings) =>
    settings.deviceAuthorizationRequestLifetimeRange,
  deviceAuthorizationPollingIntervalSeconds: (settings) =>
    settings.deviceAuthorizationPollingIntervalRange,
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
      expectedVersion: settings.version,
    },
  }
}

export interface AuthenticationDraft {
  breachedPasswordCheckEnabled: boolean
  timeCost: string
  memoryCostKib: string
  parallelism: string
}

export type HashingField = 'timeCost' | 'memoryCostKib' | 'parallelism'

export function authenticationDraft(settings: AuthenticationSettings): AuthenticationDraft {
  return {
    breachedPasswordCheckEnabled: settings.breachedPasswordCheckEnabled,
    timeCost: String(settings.passwordHashing.timeCost),
    memoryCostKib: String(settings.passwordHashing.memoryCostKib),
    parallelism: String(settings.passwordHashing.parallelism),
  }
}

export function hashingRange(settings: AuthenticationSettings, field: HashingField): SettingRange {
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
  for (const field of ['timeCost', 'memoryCostKib', 'parallelism'] as const) {
    const parsed = parseWholeNumber(draft[field], hashingRange(settings, field))
    if ('error' in parsed) errors[field] = parsed.error
    else values[field] = parsed.value
  }
  if (Object.keys(errors).length) return { errors }
  return {
    input: {
      breachedPasswordCheckEnabled: draft.breachedPasswordCheckEnabled,
      passwordHashing: {
        timeCost: values.timeCost!,
        memoryCostKib: values.memoryCostKib!,
        parallelism: values.parallelism!,
      },
      expectedVersion: settings.version,
    },
  }
}
