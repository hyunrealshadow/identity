import { validScopeSelector } from '#/lib/scope-pattern'

const CONFIG_KEYS = [
  'issuer',
  'graphqlUrl',
  'clientId',
  'redirectUri',
  'postLogoutRedirectUri',
  'accountUrl',
  'scope',
  'displayName',
  'environment',
] as const

export type RuntimeConfigKey = (typeof CONFIG_KEYS)[number]

export interface RuntimeConfig {
  issuer: string
  graphqlUrl: string
  clientId: string
  redirectUri: string
  postLogoutRedirectUri: string
  accountUrl: string
  scope: string
  displayName: string
  environment: string
}

export type ConfigErrorCode =
  | 'config_unavailable'
  | 'config_not_json'
  | 'config_not_object'
  | 'config_unexpected_keys'
  | 'config_missing_keys'
  | 'config_invalid_value'
  | 'config_invalid_url'
  | 'config_invalid_scope'
  | 'config_invalid_redirect'
  | 'config_invalid_account_url'

export class ConfigError extends Error {
  readonly code: ConfigErrorCode

  constructor(code: ConfigErrorCode, options?: { cause?: unknown }) {
    super(code, options)
    this.name = 'ConfigError'
    this.code = code
  }
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
}

function parseHttpUrl(value: unknown, allowQuery: boolean, allowFragment: boolean): URL {
  if (typeof value !== 'string' || value.trim() === '') {
    throw new ConfigError('config_invalid_url')
  }

  let url: URL
  try {
    url = new URL(value)
  } catch {
    throw new ConfigError('config_invalid_url')
  }

  if (url.protocol !== 'http:' && url.protocol !== 'https:') {
    throw new ConfigError('config_invalid_url')
  }
  if (url.username || url.password) throw new ConfigError('config_invalid_url')
  if (!url.hostname) throw new ConfigError('config_invalid_url')
  if (!allowQuery && (url.search || url.searchParams.size > 0)) {
    throw new ConfigError('config_invalid_url')
  }
  if (!allowFragment && url.hash) throw new ConfigError('config_invalid_url')
  return url
}

function requireNonEmpty(value: unknown, maxLength: number): string {
  if (typeof value !== 'string') throw new ConfigError('config_invalid_value')
  const trimmed = value.trim()
  if (!trimmed || trimmed.length > maxLength) throw new ConfigError('config_invalid_value')
  return trimmed
}

function validateScope(value: unknown): string {
  if (typeof value !== 'string') throw new ConfigError('config_invalid_scope')
  const scope = value.trim()
  if (!scope) throw new ConfigError('config_invalid_scope')

  const tokens = scope.split(/\s+/)
  const seen = new Set<string>()
  for (const token of tokens) {
    if (!validScopeSelector(token)) throw new ConfigError('config_invalid_scope')
    if (seen.has(token)) throw new ConfigError('config_invalid_scope')
    seen.add(token)
  }
  if (!seen.has('openid')) throw new ConfigError('config_invalid_scope')
  return tokens.join(' ')
}

function sameOrigin(url: URL): boolean {
  if (typeof window === 'undefined') return true
  return url.origin === window.location.origin
}

export function validateRuntimeConfig(value: unknown): RuntimeConfig {
  if (!isRecord(value)) throw new ConfigError('config_not_object')

  const keys = Object.keys(value)
  if (keys.some((key) => !(CONFIG_KEYS as readonly string[]).includes(key))) {
    throw new ConfigError('config_unexpected_keys')
  }
  if (CONFIG_KEYS.some((key) => !(key in value))) {
    throw new ConfigError('config_missing_keys')
  }

  const issuer = parseHttpUrl(value.issuer, false, false)
  const graphqlUrl = parseHttpUrl(value.graphqlUrl, true, false)
  const redirectUri = parseHttpUrl(value.redirectUri, true, false)
  const postLogoutRedirectUri = parseHttpUrl(value.postLogoutRedirectUri, true, false)
  const accountUrl = parseHttpUrl(value.accountUrl, false, false)

  if (!sameOrigin(redirectUri) || !sameOrigin(postLogoutRedirectUri)) {
    throw new ConfigError('config_invalid_redirect')
  }
  // The account center is a separate application. A same-origin account URL
  // would send the operator back into this Console instead of the account
  // area. When the browser origin is unavailable, there is nothing to compare.
  if (typeof window !== 'undefined' && accountUrl.origin === window.location.origin) {
    throw new ConfigError('config_invalid_account_url')
  }
  const clientId = requireNonEmpty(value.clientId, 512)
  if (/\s/.test(clientId)) throw new ConfigError('config_invalid_value')

  return {
    issuer: issuer.toString(),
    graphqlUrl: graphqlUrl.toString(),
    clientId,
    redirectUri: redirectUri.toString(),
    postLogoutRedirectUri: postLogoutRedirectUri.toString(),
    accountUrl: accountUrl.toString(),
    scope: validateScope(value.scope),
    displayName: requireNonEmpty(value.displayName, 120),
    environment: requireNonEmpty(value.environment, 80),
  }
}

export async function loadRuntimeConfig(
  fetchImpl: typeof fetch = globalThis.fetch.bind(globalThis),
): Promise<RuntimeConfig> {
  let response: Response
  try {
    response = await fetchImpl(new URL('/config.json', window.location.origin), {
      cache: 'no-store',
      credentials: 'omit',
      headers: { Accept: 'application/json' },
    })
  } catch (error) {
    throw new ConfigError('config_unavailable', { cause: error })
  }

  if (!response.ok) throw new ConfigError('config_unavailable')

  let payload: unknown
  try {
    payload = await response.json()
  } catch (error) {
    throw new ConfigError('config_not_json', { cause: error })
  }

  return validateRuntimeConfig(payload)
}
