export interface IdTokenClaims {
  sub: string
  iss: string
  aud: string | string[]
  exp: number
  iat?: number
  auth_time?: number
  acr?: string
  amr?: string[]
  name?: string
  preferred_username?: string
  email?: string
  email_verified?: boolean
  given_name?: string
  family_name?: string
  nickname?: string
  picture?: string
  locale?: string
  zoneinfo?: string
}

export interface AuthSession {
  accessToken: string
  idToken: string
  expiresAt: number
  scope: string
  grantedScopes: string[]
  claims: IdTokenClaims
  endSessionEndpoint?: string
}

/**
 * The only persistent location where access and ID tokens exist. They are
 * intentionally kept in a module closure and are never written to
 * localStorage, sessionStorage or cookies. The explicit single sign-out
 * protocol may place the ID token in the provider's end-session URL as
 * `id_token_hint`, as required by OIDC RP-Initiated Logout.
 */
let memorySession: AuthSession | null = null

export function setAuthSession(session: AuthSession): void {
  memorySession = session
}

export function clearAuthSession(): void {
  memorySession = null
}

export function getAuthSession(): AuthSession | null {
  return memorySession
}

/**
 * Returns a token only while the in-memory session is still unexpired. The
 * session object itself is retained during a fresh-authentication popup so
 * the workspace and its claims stay visible, but an expired token must never
 * be sent to the API.
 */
export function peekAccessToken(now: number = Date.now()): string | null {
  if (!memorySession) return null
  if (memorySession.expiresAt <= now) return null
  return memorySession.accessToken
}
