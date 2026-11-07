import { parseDate } from '@internationalized/date'

import type {
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

export type ClientKind = 'web' | 'spa' | 'native' | 'machine'

/** Protocol settings as edited: URI lists are one entry per line. */
export interface ClientSettingsDraft {
  webRedirectUris: string
  nativeRedirectUris: string
  postLogoutRedirectUris: string
  grantTypes: ClientGrantType[]
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

interface ClientSettingsSource {
  platforms: ReadonlyArray<{ platform: string; redirectUris: readonly string[] }>
  postLogoutRedirectUris: readonly string[]
  grantTypes: readonly ClientGrantType[]
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
      return { ...base, allowPublicClientFlow: true, corsEnabled: true }
    case 'native':
      return { ...base, allowPublicClientFlow: true }
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
    allowPublicClientFlow: draft.allowPublicClientFlow,
    requirePushedAuthorizationRequests: draft.requirePushedAuthorizationRequests,
    skipConsent: draft.skipConsent,
    corsEnabled: draft.corsEnabled,
    oauthVersion: draft.oauthVersion,
    includeScopedClaimsInIdToken: draft.includeScopedClaimsInIdToken,
    includeScopedClaimsInAccessToken: draft.includeScopedClaimsInAccessToken,
  }
}

/** Whether a kind of client keeps a secret, so creating one leads to issuing it. */
export function kindUsesSecret(kind: ClientKind): boolean {
  return kind === 'web' || kind === 'machine'
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

/** Usable credentials a client may hold at once, per kind (mirrors the server). */
export const MAX_ACTIVE_CREDENTIALS = {
  CLIENT_SECRET: 5,
  PUBLIC_KEY: 5,
  JWKS_URI: 1,
} as const

/** Bullets shown before a secret's last characters; the server stores no mask. */
const SECRET_MASK = '••••••••'

/** A secret hint as shown: a fixed mask followed by the stored last characters. */
export function maskedSecretHint(hint: string): string {
  return `${SECRET_MASK}${hint}`
}

/** A long identifier (a key thumbprint) shortened for a table cell. */
export function shortHint(hint: string, keep = 12): string {
  return hint.length > keep ? `${hint.slice(0, keep)}…` : hint
}

/**
 * The instant a key chosen to expire "on" a calendar day stops working: the
 * start of the following day in the viewer's time zone, so the whole chosen
 * day stays valid.
 */
export function keyExpiryInstant(day: string, timeZone: string): string | null {
  try {
    return parseDate(day).add({ days: 1 }).toDate(timeZone).toISOString()
  } catch {
    return null
  }
}

/** Whether pasted key text is a certificate, which brings its own expiry. */
export function isCertificatePem(value: string): boolean {
  return value.includes('-----BEGIN CERTIFICATE-----')
}
