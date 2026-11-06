import type {
  ClientAuthMethod,
  ClientGrantType,
  ClientOAuthVersion,
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
  tokenEndpointAuthMethods: ClientAuthMethod[]
  allowPublicClientFlow: boolean
  requirePushedAuthorizationRequests: boolean
  skipConsent: boolean
  corsEnabled: boolean
  /** `null` inherits the instance's live OAuth version. */
  oauthVersion: ClientOAuthVersion | null
  includeScopedClaimsInIdToken: boolean
  includeScopedClaimsInAccessToken: boolean
}

export type ClientSettingsField =
  | 'webRedirectUris'
  | 'nativeRedirectUris'
  | 'postLogoutRedirectUris'
  | 'grantTypes'
  | 'tokenEndpointAuthMethods'

interface ClientSettingsSource {
  platforms: ReadonlyArray<{ platform: string; redirectUris: readonly string[] }>
  postLogoutRedirectUris: readonly string[]
  grantTypes: readonly ClientGrantType[]
  tokenEndpointAuthMethods: readonly ClientAuthMethod[]
  allowPublicClientFlow: boolean
  requirePushedAuthorizationRequests: boolean
  skipConsent: boolean
  corsEnabled: boolean
  oauthVersion?: ClientOAuthVersion | null
  includeScopedClaimsInIdToken?: boolean
  includeScopedClaimsInAccessToken?: boolean
}

/** A starting point per application kind; every value stays editable. */
export function settingsForKind(kind: ClientKind): ClientSettingsDraft {
  const base: ClientSettingsDraft = {
    webRedirectUris: '',
    nativeRedirectUris: '',
    postLogoutRedirectUris: '',
    grantTypes: ['AUTHORIZATION_CODE', 'REFRESH_TOKEN'],
    tokenEndpointAuthMethods: ['CLIENT_SECRET_BASIC'],
    allowPublicClientFlow: false,
    requirePushedAuthorizationRequests: false,
    skipConsent: false,
    corsEnabled: false,
    oauthVersion: null,
    includeScopedClaimsInIdToken: false,
    includeScopedClaimsInAccessToken: false,
  }
  switch (kind) {
    case 'web':
      return base
    case 'spa':
      return {
        ...base,
        tokenEndpointAuthMethods: ['NONE'],
        allowPublicClientFlow: true,
        corsEnabled: true,
      }
    case 'native':
      return { ...base, tokenEndpointAuthMethods: ['NONE'], allowPublicClientFlow: true }
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
    tokenEndpointAuthMethods: [...client.tokenEndpointAuthMethods],
    allowPublicClientFlow: client.allowPublicClientFlow,
    requirePushedAuthorizationRequests:
      client.requirePushedAuthorizationRequests,
    skipConsent: client.skipConsent,
    corsEnabled: client.corsEnabled,
    oauthVersion: client.oauthVersion ?? null,
    includeScopedClaimsInIdToken: client.includeScopedClaimsInIdToken ?? false,
    includeScopedClaimsInAccessToken:
      client.includeScopedClaimsInAccessToken ?? false,
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
    // Stable order so an unchanged selection compares equal to the stored one.
    tokenEndpointAuthMethods: [
      ...SELECTABLE_AUTH_METHODS.filter((method) =>
        draft.tokenEndpointAuthMethods.includes(method),
      ),
      ...draft.tokenEndpointAuthMethods.filter(
        (method) => !SELECTABLE_AUTH_METHODS.includes(method),
      ),
    ],
    allowPublicClientFlow: draft.allowPublicClientFlow,
    requirePushedAuthorizationRequests: draft.requirePushedAuthorizationRequests,
    skipConsent: draft.skipConsent,
    corsEnabled: draft.corsEnabled,
    oauthVersion: draft.oauthVersion,
    includeScopedClaimsInIdToken: draft.includeScopedClaimsInIdToken,
    includeScopedClaimsInAccessToken: draft.includeScopedClaimsInAccessToken,
  }
}

export function isSecretMethod(method: ClientAuthMethod): boolean {
  return (
    method === 'CLIENT_SECRET_BASIC' ||
    method === 'CLIENT_SECRET_POST' ||
    method === 'CLIENT_SECRET_JWT'
  )
}

/** Whether any configured method authenticates with a client secret. */
export function usesClientSecret(methods: readonly ClientAuthMethod[]): boolean {
  return methods.some(isSecretMethod)
}

/** Turn one method on or off; any combination is allowed. */
export function toggleAuthMethod(
  methods: readonly ClientAuthMethod[],
  method: ClientAuthMethod,
  on: boolean,
): ClientAuthMethod[] {
  const rest = methods.filter((value) => value !== method)
  return on ? [...rest, method] : rest
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
    grants.includes('CLIENT_CREDENTIALS') &&
    !usesClientSecret(draft.tokenEndpointAuthMethods)
  ) {
    errors.grantTypes = 'clientsGrantPublicMachine'
  }
  const methods = draft.tokenEndpointAuthMethods
  if (methods.length === 0) {
    errors.tokenEndpointAuthMethods = 'clientsAuthMethodRequired'
  } else if (methods.some((method) => !SELECTABLE_AUTH_METHODS.includes(method))) {
    errors.tokenEndpointAuthMethods = 'clientsAuthMethodUnsupported'
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
  if (path.startsWith('tokenEndpointAuthMethods')) return 'tokenEndpointAuthMethods'
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

/**
 * Identity of the server state an edit form was seeded from. A mutation first
 * patches only the cached `version`; the refetch that follows brings the saved
 * fields and a new `updatedAt`. Keying on both re-seeds the form once the real
 * values arrive instead of keeping a draft built from the patched snapshot.
 */
export function formSeed(client: { version: string; updatedAt?: string | null }): string {
  return `${client.version}:${client.updatedAt ?? ''}`
}
