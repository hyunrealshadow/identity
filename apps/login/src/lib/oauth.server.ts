import { createHash, randomBytes, timingSafeEqual } from 'node:crypto'

import { translate } from './i18n'
import { requestLocale } from './i18n.server'
import {
  type OAuthFlowSession,
  type OAuthTokenSession,
  useAuthorizationSession,
  useAccountFlashSession,
  useOAuthFlowSession,
  useMfaUiSession,
  storeAccountFlash,
} from './oauth-session.server'
import { loadApplicationUrl, loadOAuthClient } from './runtime-config.server'

const API_URL = process.env.IDENTITY_API_URL ?? 'https://localhost:5150'
const API_RESOURCE = 'urn:identity:graphql'
const SCOPES =
  'openid profile email offline_access account session password.change'
const REAUTHENTICATION_SCOPES = {
  password: 'openid password.change',
  account: 'openid account',
  mfa: 'openid account',
} as const
const ACR_AAL1 = 'urn:identity:acr:aal1'
const ACR_AAL2 = 'urn:identity:acr:aal2'
const RECENT_AUTHENTICATION_SECONDS = 5 * 60
const ELEVATED_AUTHENTICATION_SECONDS = 60 * 60

interface TokenResponse {
  access_token: string
  refresh_token?: string
  id_token?: string
  expires_in: number
}

interface TokenErrorResponse {
  error?: string
  error_description?: string
}

interface ReauthenticationRequirements {
  loginHint: string
  acrValues?: string
  maxAge?: number
}

const pendingTokenExchanges = new Map<string, Promise<TokenResponse>>()

export class OAuthTokenExchangeError extends Error {
  readonly grantType: string
  readonly oauthError?: string
  readonly status: number

  constructor(
    grantType: string,
    status: number,
    oauthError?: string,
    description?: string,
  ) {
    const detail = [oauthError, description].filter(Boolean).join(': ')
    super(
      detail
        ? `OAuth ${grantType} exchange failed: ${detail}`
        : `OAuth ${grantType} exchange failed (${status})`,
    )
    this.name = 'OAuthTokenExchangeError'
    this.grantType = grantType
    this.oauthError = oauthError
    this.status = status
  }
}

export async function prepareAuthorization() {
  return startAuthorizationFlow('signin', '/')
}

export async function startReauthorization(
  returnTo: string | undefined,
  purpose: 'password' | 'account' | 'mfa' = 'password',
  requirements: ReauthenticationRequirements,
) {
  return redirect(
    await startAuthorizationFlow(
      'reauth',
      safeReturnTo(returnTo, '/?message=reauthenticated'),
      purpose,
      requirements,
    ),
  )
}

export function reauthenticationScope(
  purpose: 'password' | 'account' | 'mfa',
) {
  return REAUTHENTICATION_SCOPES[purpose]
}

export function reauthenticationRequestParameters(
  purpose: 'password' | 'account' | 'mfa',
  requirements: ReauthenticationRequirements,
) {
  return {
    loginHint: requirements.loginHint,
    maxAge: requirements.maxAge ?? 0,
    acrValues:
      requirements.acrValues ?? (purpose === 'mfa' ? ACR_AAL2 : ACR_AAL1),
  }
}

async function startAuthorizationFlow(
  mode: OAuthFlowSession['mode'],
  returnTo: string,
  reauthPurpose: 'password' | 'account' | 'mfa' = 'password',
  requirements?: ReauthenticationRequirements,
) {
  const oauthClient = await loadOAuthClient()
  const state = randomBytes(32).toString('base64url')
  const verifier = randomBytes(48).toString('base64url')
  const challenge = createHash('sha256').update(verifier).digest('base64url')
  const redirectUri = callbackUrl(loadApplicationUrl())
  const authorizeUrl = new URL('/oauth2/authorize', API_URL)
  authorizeUrl.search = new URLSearchParams({
    response_type: 'code',
    client_id: oauthClient.client_id,
    redirect_uri: redirectUri,
    scope:
      mode === 'reauth'
        ? reauthenticationScope(reauthPurpose)
        : SCOPES,
    resource: API_RESOURCE,
    state,
    code_challenge: challenge,
    code_challenge_method: 'S256',
  }).toString()
  if (mode === 'reauth') {
    if (!requirements) {
      throw new Error('Reauthentication requires a login hint')
    }
    const parameters = reauthenticationRequestParameters(
      reauthPurpose,
      requirements,
    )
    authorizeUrl.searchParams.set('max_age', String(parameters.maxAge))
    authorizeUrl.searchParams.set('acr_values', parameters.acrValues)
    authorizeUrl.searchParams.set('login_hint', parameters.loginHint)
  }

  const flow = await useOAuthFlowSession()
  await flow.update({
    state,
    verifier,
    mode,
    return_to: returnTo,
    reauth_purpose: mode === 'reauth' ? reauthPurpose : undefined,
  } satisfies OAuthFlowSession)

  return authorizeUrl
}

export async function finishAuthorization(request: Request) {
  const url = new URL(request.url)
  const code = url.searchParams.get('code')
  const returnedState = url.searchParams.get('state')
  const flow = await useOAuthFlowSession()
  const stateMatches =
    !!returnedState &&
    typeof flow.data.state === 'string' &&
    constantTimeEqual(returnedState, flow.data.state)

  if (url.searchParams.has('error')) {
    if (!stateMatches) {
      return new Response(translate(requestLocale(), 'oauthCallbackInvalid'), {
        status: 400,
      })
    }
    await clearFailedAuthorization(flow)
    return authorizationFailureResponse(
      request,
      url.searchParams.get('error'),
      url.searchParams.get('error_description'),
    )
  }

  if (
    !code ||
    !stateMatches ||
    typeof flow.data.verifier !== 'string'
  ) {
    return new Response(translate(requestLocale(), 'oauthCallbackInvalid'), {
      status: 400,
    })
  }

  const oauthClient = await loadOAuthClient()
  let tokens: TokenResponse
  try {
    tokens = await exchangeToken(
      new URLSearchParams({
        grant_type: 'authorization_code',
        code,
        redirect_uri: callbackUrl(loadApplicationUrl()),
        code_verifier: flow.data.verifier,
      }),
      oauthClient.client_id,
      oauthClient.client_secret,
    )
  } catch (error) {
    if (error instanceof OAuthTokenExchangeError) {
      await clearFailedAuthorization(flow)
      return authorizationFailureResponse(request, error.oauthError, error.message)
    }
    throw error
  }

  const authorization = await useAuthorizationSession()
  const mode = flow.data.mode === 'reauth' ? 'reauth' : 'signin'
  const returnTo = safeReturnTo(flow.data.return_to, '/')
  if (mode === 'reauth') {
    await authorization.update({
      elevated_access_token: tokens.access_token,
      elevated_expires_at: Date.now() + tokens.expires_in * 1000,
    })
    await storeAccountFlash({ message: 'reauthenticated' })
  } else {
    await authorization.update(toStoredTokens(tokens))
  }
  await flow.clear()

  return redirect(new URL(returnTo, loadApplicationUrl()))
}

function authorizationFailureResponse(
  request: Request,
  error: string | undefined | null,
  description: string | undefined | null,
) {
  const destination = new URL('/authorization-error', request.url)
  destination.searchParams.set('error', error || 'invalid_request')
  if (description?.trim()) {
    destination.searchParams.set('error_description', description.trim())
  }
  return redirect(destination)
}

async function clearFailedAuthorization(
  flow: Awaited<ReturnType<typeof useOAuthFlowSession>>,
) {
  const mode = flow.data.mode === 'reauth' ? 'reauth' : 'signin'
  await flow.clear()
  await clearMfaUiState()
  if (mode === 'reauth') {
    await clearElevatedAuthorization()
  } else {
    await clearAuthorizationCookie()
  }
}

export async function clearAuthorizationCookie() {
  await (await useAuthorizationSession()).clear()
  await (await useMfaUiSession()).clear()
  await (await useAccountFlashSession()).clear()
}

export async function finishLogout(applicationUrl: string) {
  const authorization = await useAuthorizationSession()
  const idToken =
    typeof authorization.data.id_token === 'string'
      ? authorization.data.id_token
      : undefined
  await authorization.clear()
  await (await useMfaUiSession()).clear()
  await (await useAccountFlashSession()).clear()
  if (idToken) {
    const logoutUrl = new URL('/oauth2/logout', API_URL)
    logoutUrl.search = new URLSearchParams({
      id_token_hint: idToken,
      post_logout_redirect_uri: new URL('/', applicationUrl).toString(),
    }).toString()
    return new Response(null, {
      status: 303,
      headers: { location: logoutUrl.toString() },
    })
  }
  return new Response(null, {
    status: 303,
    headers: { location: new URL('/', applicationUrl).toString() },
  })
}

export async function elevatedAccessToken() {
  const session = await useAuthorizationSession()
  if (
    typeof session.data.elevated_access_token !== 'string' ||
    typeof session.data.elevated_expires_at !== 'number' ||
    session.data.elevated_expires_at <= Date.now() + 5_000
  ) {
    return
  }
  return session.data.elevated_access_token
}

export async function hasFreshAuthentication(requiredAcr?: string) {
  const tokens = [await elevatedAccessToken(), await accessToken()]
  return tokens.some(
    (token) => token && tokenAuthenticationIsFresh(token, requiredAcr),
  )
}

export function tokenAuthenticationIsFresh(
  token: string,
  requiredAcr?: string,
  now = Math.floor(Date.now() / 1000),
) {
  try {
    const encodedPayload = token.split('.')[1]
    if (!encodedPayload) return false
    const claims = JSON.parse(
      Buffer.from(encodedPayload, 'base64url').toString('utf8'),
    ) as { auth_time?: unknown; acr?: unknown }
    if (typeof claims.auth_time !== 'number' || typeof claims.acr !== 'string') {
      return false
    }
    if (requiredAcr && claims.acr !== requiredAcr) return false
    const maxAge = requiredAcr === ACR_AAL2
      ? ELEVATED_AUTHENTICATION_SECONDS
      : RECENT_AUTHENTICATION_SECONDS
    return Math.max(0, now - claims.auth_time) <= maxAge
  } catch {
    return false
  }
}

export async function clearElevatedAuthorization() {
  await (
    await useAuthorizationSession()
  ).update({
    elevated_access_token: undefined,
    elevated_expires_at: undefined,
  })
}

export async function mfaUiState() {
  const session = await useMfaUiSession()
  return {
    enrollment: session.data.mfa_enrollment,
    recoveryCodes: session.data.regenerated_recovery_codes,
  }
}

export async function storeMfaEnrollment(enrollment: {
  secret: string
  otp_auth_uri: string
  enrollment_token: string
  recovery_codes: Array<string>
}) {
  await (await useMfaUiSession()).update({
    mfa_enrollment: enrollment,
  })
}

export async function clearMfaUiState() {
  await (await useMfaUiSession()).update({
    mfa_enrollment: undefined,
    regenerated_recovery_codes: undefined,
  })
}

export async function storeRegeneratedRecoveryCodes(recoveryCodes: Array<string>) {
  await (await useMfaUiSession()).update({
    regenerated_recovery_codes: recoveryCodes,
  })
}

export async function accessToken() {
  const session = await useAuthorizationSession()
  const stored = storedTokens(session.data)
  if (!stored) return
  if (stored.expires_at > Date.now() + 30_000) return stored.access_token
  if (!stored.refresh_token) return

  const oauthClient = await loadOAuthClient()
  let refreshed: TokenResponse
  try {
    refreshed = await exchangeToken(
      new URLSearchParams({
        grant_type: 'refresh_token',
        refresh_token: stored.refresh_token,
      }),
      oauthClient.client_id,
      oauthClient.client_secret,
    )
  } catch (error) {
    if (
      error instanceof OAuthTokenExchangeError &&
      error.oauthError === 'invalid_grant'
    ) {
      await session.clear()
      return
    }
    throw error
  }
  const next = toStoredTokens({
    ...refreshed,
    refresh_token: refreshed.refresh_token ?? stored.refresh_token,
    id_token: refreshed.id_token ?? stored.id_token,
  })
  await session.update(next)
  return next.access_token
}

function toStoredTokens(tokens: TokenResponse): OAuthTokenSession {
  return {
    access_token: tokens.access_token,
    refresh_token: tokens.refresh_token,
    id_token: tokens.id_token,
    expires_at: Date.now() + tokens.expires_in * 1000,
  }
}

function storedTokens(
  data: Partial<OAuthTokenSession>,
): OAuthTokenSession | undefined {
  if (
    typeof data.access_token !== 'string' ||
    typeof data.expires_at !== 'number' ||
    (data.refresh_token !== undefined &&
      typeof data.refresh_token !== 'string') ||
    (data.id_token !== undefined && typeof data.id_token !== 'string')
  ) {
    return
  }
  return data as OAuthTokenSession
}

export async function exchangeToken(
  body: URLSearchParams,
  clientId: string,
  clientSecret: string,
) {
  const exchangeKey = createHash('sha256')
    .update(clientId)
    .update('\0')
    .update(clientSecret)
    .update('\0')
    .update(body.toString())
    .digest('base64url')
  const pending = pendingTokenExchanges.get(exchangeKey)
  if (pending) return pending

  const exchange = performTokenExchange(body, clientId, clientSecret)
  pendingTokenExchanges.set(exchangeKey, exchange)
  try {
    return await exchange
  } finally {
    if (pendingTokenExchanges.get(exchangeKey) === exchange) {
      pendingTokenExchanges.delete(exchangeKey)
    }
  }
}

async function performTokenExchange(
  body: URLSearchParams,
  clientId: string,
  clientSecret: string,
) {
  const response = await fetch(new URL('/oauth2/token', API_URL), {
    method: 'POST',
    headers: {
      accept: 'application/json',
      authorization: `Basic ${Buffer.from(`${clientId}:${clientSecret}`).toString('base64')}`,
      'content-type': 'application/x-www-form-urlencoded',
    },
    body,
  })
  const payload = (await response.json().catch(() => null)) as
    | TokenResponse
    | TokenErrorResponse
    | null
  if (!response.ok || !payload || !('access_token' in payload)) {
    const grant = body.get('grant_type') ?? 'unknown grant'
    const oauthError = payload?.error?.trim()
    const description = payload?.error_description?.trim()
    throw new OAuthTokenExchangeError(
      grant,
      response.status,
      oauthError,
      description,
    )
  }
  return payload
}

export function callbackUrl(applicationUrl: string) {
  return new URL('/callback', applicationUrl).toString()
}

export function safeReturnTo(value: string | undefined, fallback: string) {
  if (!value || !value.startsWith('/') || value.startsWith('//')) {
    return fallback
  }
  try {
    const url = new URL(value, 'https://identity.invalid')
    return `${url.pathname}${url.search}${url.hash}`
  } catch {
    return fallback
  }
}

function redirect(location: URL) {
  return new Response(null, {
    status: 302,
    headers: { location: location.toString() },
  })
}

function constantTimeEqual(left: string, right: string) {
  const leftBytes = Buffer.from(left)
  const rightBytes = Buffer.from(right)
  return (
    leftBytes.length === rightBytes.length &&
    timingSafeEqual(leftBytes, rightBytes)
  )
}
