import type {
  ClientAuthMethod,
  ClientGrantType,
  ClientSettingsInput,
} from '#/generated/graphql'
import type { MessageKey } from '#/lib/i18n'

/** Grant types an administrator can select; implicit is display-only. */
export const SELECTABLE_GRANT_TYPES: readonly ClientGrantType[] = [
  'AUTHORIZATION_CODE',
  'REFRESH_TOKEN',
  'CLIENT_CREDENTIALS',
  'DEVICE_CODE',
]

/** Methods an administrator can select; key-based methods are display-only. */
export const SELECTABLE_AUTH_METHODS: readonly ClientAuthMethod[] = [
  'CLIENT_SECRET_BASIC',
  'CLIENT_SECRET_POST',
  'CLIENT_SECRET_JWT',
  'NONE',
]

export type ClientKind = 'web' | 'spa' | 'native' | 'machine'

/** Protocol settings as edited: URI lists are one entry per line. */
export interface ClientSettingsDraft {
  webRedirectUris: string
  nativeRedirectUris: string
  postLogoutRedirectUris: string
  grantTypes: ClientGrantType[]
  tokenEndpointAuthMethod: ClientAuthMethod
  requirePushedAuthorizationRequests: boolean
  skipConsent: boolean
  corsEnabled: boolean
}

export type ClientSettingsField =
  | 'webRedirectUris'
  | 'nativeRedirectUris'
  | 'postLogoutRedirectUris'
  | 'grantTypes'
  | 'tokenEndpointAuthMethod'

interface ClientSettingsSource {
  platforms: ReadonlyArray<{ platform: string; redirectUris: readonly string[] }>
  postLogoutRedirectUris: readonly string[]
  grantTypes: readonly ClientGrantType[]
  tokenEndpointAuthMethod: ClientAuthMethod
  requirePushedAuthorizationRequests: boolean
  skipConsent: boolean
  corsEnabled: boolean
}

/** A starting point per application kind; every value stays editable. */
export function settingsForKind(kind: ClientKind): ClientSettingsDraft {
  const base: ClientSettingsDraft = {
    webRedirectUris: '',
    nativeRedirectUris: '',
    postLogoutRedirectUris: '',
    grantTypes: ['AUTHORIZATION_CODE', 'REFRESH_TOKEN'],
    tokenEndpointAuthMethod: 'CLIENT_SECRET_BASIC',
    requirePushedAuthorizationRequests: false,
    skipConsent: false,
    corsEnabled: false,
  }
  switch (kind) {
    case 'web':
      return base
    case 'spa':
      return { ...base, tokenEndpointAuthMethod: 'NONE', corsEnabled: true }
    case 'native':
      return { ...base, tokenEndpointAuthMethod: 'NONE' }
    case 'machine':
      return { ...base, grantTypes: ['CLIENT_CREDENTIALS'] }
  }
}

export function settingsDraftFromClient(
  client: ClientSettingsSource,
): ClientSettingsDraft {
  const uris = (platform: string) =>
    (
      client.platforms.find((entry) => entry.platform === platform)
        ?.redirectUris ?? []
    ).join('\n')
  return {
    webRedirectUris: uris('WEB'),
    nativeRedirectUris: uris('NATIVE'),
    postLogoutRedirectUris: client.postLogoutRedirectUris.join('\n'),
    grantTypes: [...client.grantTypes],
    tokenEndpointAuthMethod: client.tokenEndpointAuthMethod,
    requirePushedAuthorizationRequests:
      client.requirePushedAuthorizationRequests,
    skipConsent: client.skipConsent,
    corsEnabled: client.corsEnabled,
  }
}

export function uriLines(value: string): string[] {
  return [
    ...new Set(
      value
        .split(/\r?\n/u)
        .map((line) => line.trim())
        .filter(Boolean),
    ),
  ]
}

export function settingsInput(draft: ClientSettingsDraft): ClientSettingsInput {
  const platforms: ClientSettingsInput['platforms'] = []
  const web = uriLines(draft.webRedirectUris)
  const native = uriLines(draft.nativeRedirectUris)
  if (web.length) platforms.push({ platform: 'WEB', redirectUris: web })
  if (native.length) platforms.push({ platform: 'NATIVE', redirectUris: native })
  return {
    platforms,
    postLogoutRedirectUris: uriLines(draft.postLogoutRedirectUris),
    grantTypes: SELECTABLE_GRANT_TYPES.filter((grant) =>
      draft.grantTypes.includes(grant),
    ),
    tokenEndpointAuthMethod: draft.tokenEndpointAuthMethod,
    requirePushedAuthorizationRequests: draft.requirePushedAuthorizationRequests,
    skipConsent: draft.skipConsent,
    corsEnabled: draft.corsEnabled,
  }
}

export function usesClientSecret(method: ClientAuthMethod): boolean {
  return (
    method === 'CLIENT_SECRET_BASIC' ||
    method === 'CLIENT_SECRET_POST' ||
    method === 'CLIENT_SECRET_JWT'
  )
}

/**
 * Interaction-level checks that mirror the server's rules. The server remains
 * authoritative; this only avoids a round trip for obvious mistakes.
 */
export function validateSettings(
  draft: ClientSettingsDraft,
): Partial<Record<ClientSettingsField, MessageKey>> {
  const errors: Partial<Record<ClientSettingsField, MessageKey>> = {}
  const grants = draft.grantTypes
  const unsupportedGrant = grants.some(
    (grant) => !SELECTABLE_GRANT_TYPES.includes(grant),
  )
  if (grants.length === 0 || unsupportedGrant) {
    errors.grantTypes = unsupportedGrant
      ? 'clientsGrantImplicitUnsupported'
      : 'clientsGrantRequired'
  } else if (
    grants.includes('REFRESH_TOKEN') &&
    !grants.includes('AUTHORIZATION_CODE') &&
    !grants.includes('DEVICE_CODE')
  ) {
    errors.grantTypes = 'clientsGrantRefreshNeedsInteractive'
  } else if (
    draft.tokenEndpointAuthMethod === 'NONE' &&
    grants.includes('CLIENT_CREDENTIALS')
  ) {
    errors.grantTypes = 'clientsGrantPublicMachine'
  }
  if (!SELECTABLE_AUTH_METHODS.includes(draft.tokenEndpointAuthMethod)) {
    errors.tokenEndpointAuthMethod = 'clientsAuthMethodUnsupported'
  }
  if (
    grants.includes('AUTHORIZATION_CODE') &&
    uriLines(draft.webRedirectUris).length === 0 &&
    uriLines(draft.nativeRedirectUris).length === 0
  ) {
    errors.webRedirectUris = 'clientsRedirectRequired'
  }
  return errors
}

/** Map server field paths onto the form fields that show them. */
export function settingsFieldFor(path: string): ClientSettingsField | undefined {
  if (path.startsWith('platforms')) return 'webRedirectUris'
  if (path.startsWith('postLogoutRedirectUris')) return 'postLogoutRedirectUris'
  if (path.startsWith('grantTypes')) return 'grantTypes'
  if (path.startsWith('tokenEndpointAuthMethod')) return 'tokenEndpointAuthMethod'
  return undefined
}

export interface ClientFieldErrors {
  settings: Partial<Record<ClientSettingsField, string>>
  /** Display text fields keyed by `name`, `names`, `description`, `descriptions`. */
  text: Record<string, string>
}

/** Route server field errors to the form section that shows them. */
export function clientFieldErrors(
  issues: ReadonlyArray<{
    fields: ReadonlyArray<{ path: string; message?: string; code?: unknown }>
  }>,
): ClientFieldErrors {
  const result: ClientFieldErrors = { settings: {}, text: {} }
  for (const issue of issues) {
    for (const field of issue.fields) {
      const message =
        field.message ?? (field.code !== undefined ? String(field.code) : '')
      const path = field.path.replace(/^input\./u, '').replace(/^settings\./u, '')
      const setting = settingsFieldFor(path)
      if (setting) {
        result.settings[setting] ??= message
      } else {
        const key = path.split('.')[0] ?? path
        result.text[key] ??= message
      }
    }
  }
  return result
}
