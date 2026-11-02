import { createHash, randomBytes, timingSafeEqual } from 'node:crypto'

import { translate } from './i18n'
import { requestLocale } from './i18n.server'
import { forwardRequestContext } from './request-context.server'
import { PASSWORD_CHANGE_CONTINUATION } from './account-reauth'
import {
  ACCOUNT_REAUTH_MESSAGE_TYPE,
  type AccountReauthMessage,
  type AccountReauthRequest,
  type AccountReauthResult,
} from './popup-reauth'
import {
  type OAuthFlowSession,
  type OAuthTokenSession,
  useAuthorizationSession,
  useAccountFlashSession,
  useOAuthFlowSession,
  useMfaUiSession,
  storeAccountFlash,
} from './oauth-session.server'
import { emitEvent, fetchWithSpan, withSpan } from './observability.server'
import { providerSessionCookie } from './identity.server'
import { loadApplicationUrl, loadOAuthClient } from './runtime-config.server'
import {
  backchannelIdentityApiUrl,
  publicIdentityApiUrl,
} from './identity-url.server'

const API_RESOURCE = 'urn:identity:graphql'
const SCOPES =
  'openid profile email offline_access account.* session.* password.change'
const REAUTHENTICATION_SCOPES = {
  password: 'openid password.change',
  account: 'openid account.*',
  mfa: 'openid account.*',
} as const
const ACR_AAL1 = 'aal1'
const ACR_AAL2 = 'aal2'

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

/**
 * The account-switch flag is stored alongside the ordinary sign-in flow. It is
 * an extension of the existing flow shape so the cookie format stays the same
 * apart from one additive, non-secret boolean.
 */
type SelectAccountFlow = OAuthFlowSession & { select_account?: boolean }

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

export async function prepareAuthorization(options?: {
  selectAccount?: boolean
}) {
  return startSignIn(undefined, options)
}

export async function startSignIn(
  returnTo?: string,
  options?: { selectAccount?: boolean },
) {
  return startAuthorizationFlow('signin', safeReturnTo(returnTo, '/'), {
    selectAccount: options?.selectAccount === true,
  })
}

/** Clear rejected account credentials before starting ordinary top-level sign-in. */
export async function restartAccountSignIn(returnTo: string) {
  await clearAuthorizationCookie()
  emitEvent('account.authentication.recovery', { outcome: 'started', reason: 'session_invalid' })
  return startSignIn(returnTo)
}

/**
 * Starts a normal sign-in that asks the provider to show account selection.
 * It deliberately uses no prior-account login hint and no subject binding.
 */
export async function startAccountSwitch(returnTo = '/account/profile') {
  return redirect(await startSignIn(returnTo, { selectAccount: true }))
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
      { reauthPurpose: purpose, requirements },
    ),
  )
}

/**
 * Starts the same bounded reauthentication, but keeps the browser in the
 * account-center popup. The callback posts a small state-bound result to the
 * configured Login application origin instead of navigating the whole page.
 */
export async function startPopupReauthorization(
  returnTo: string | undefined,
  purpose: 'password' | 'account' | 'mfa' = 'password',
  requirements: ReauthenticationRequirements,
): Promise<AccountReauthRequest> {
  const authorizeUrl = await startAuthorizationFlow(
    'reauth',
    safeReturnTo(returnTo, '/?message=reauthenticated'),
    { reauthPurpose: purpose, requirements, popup: true },
  )
  const state = authorizeUrl.searchParams.get('state')
  if (!state) throw new Error('Reauthentication state is missing')
  return { url: authorizeUrl.toString(), state }
}

/** Retries only the sealed pending flow, with a fresh state and PKCE verifier. */
export async function restartPopupReauthorization(state: string) {
  const flow = await useOAuthFlowSession()
  if (!state || flow.data.mode !== 'reauth' || !flow.data.popup ||
      !flow.data.state || !constantTimeEqual(state, flow.data.state) ||
      !flow.data.reauth_requirements) {
    return undefined
  }
  return startPopupReauthorization(
    flow.data.return_to,
    flow.data.reauth_purpose,
    flow.data.reauth_requirements,
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

/**
 * Account switching is an explicit normal sign-in mode. Reauthentication must
 * stay bound to the account that started it, so combining both is rejected
 * instead of silently weakening the subject binding.
 */
export function resolveAccountSelection(
  mode: OAuthFlowSession['mode'],
  selectAccount: boolean | undefined,
): boolean {
  if (mode === 'reauth' && selectAccount) {
    throw new Error('Reauthentication cannot switch accounts')
  }
  return mode === 'signin' && selectAccount === true
}

async function startAuthorizationFlow(
  mode: OAuthFlowSession['mode'],
  returnTo: string,
  options?: {
    reauthPurpose?: 'password' | 'account' | 'mfa'
    requirements?: ReauthenticationRequirements
    selectAccount?: boolean
    popup?: boolean
  }
) {
  const reauthPurpose = options?.reauthPurpose ?? 'password'
  const requirements = options?.requirements
  const selectAccount = resolveAccountSelection(mode, options?.selectAccount)
  const popup = options?.popup === true
  if (popup && mode !== 'reauth') {
    throw new Error('Only reauthentication can use a popup')
  }
  const oauthClient = await loadOAuthClient()
  const state = randomBytes(32).toString('base64url')
  const verifier = randomBytes(48).toString('base64url')
  const challenge = createHash('sha256').update(verifier).digest('base64url')
  const redirectUri = callbackUrl(loadApplicationUrl())
  const authorizeUrl = new URL('/oauth2/authorize', publicIdentityApiUrl())
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
  } else if (selectAccount) {
    // Only the explicit switch-account mode asks the provider to choose an
    // account. It intentionally carries no prior-user hint or binding.
    authorizeUrl.searchParams.set('prompt', 'select_account')
  }

  const flow = await useOAuthFlowSession()
  const flowData: SelectAccountFlow = {
    state,
    verifier,
    mode,
    return_to: returnTo,
    reauth_purpose: mode === 'reauth' ? reauthPurpose : undefined,
    select_account: selectAccount ? true : undefined,
    popup: popup ? true : undefined,
    reauth_requirements: popup ? requirements : undefined,
  }
  await flow.update(flowData)

  return authorizeUrl
}

export async function finishAuthorization(request: Request) {
  const result = await finishAuthorizationInner(request)
  const popupResult = result.headers.get('x-identity-reauth-result')
  const succeeded =
    (result.status >= 300 && result.status < 400) ||
    popupResult === 'success'
  emitEvent('login.callback.result', {
    outcome: succeeded ? 'success' : 'rejected',
    reason: succeeded
      ? undefined
      : result.status === 400
        ? 'invalid_callback'
        : popupResult === 'cancelled'
          ? 'cancelled'
          : 'provider_error',
    category: 'audit',
  })
  return result
}

async function finishAuthorizationInner(request: Request): Promise<Response> {
  const url = new URL(request.url)
  const code = url.searchParams.get('code')
  const returnedState = url.searchParams.get('state')
  const flow = await useOAuthFlowSession()
  const flowState =
    typeof flow.data.state === 'string' ? flow.data.state : ''
  const flowReturnTo = safeReturnTo(flow.data.return_to, '/')
  const popupReauth =
    flow.data.mode === 'reauth' && flow.data.popup === true
  const stateMatches =
    !!returnedState &&
    !!flowState &&
    constantTimeEqual(returnedState, flowState)

  if (url.searchParams.has('error')) {
    if (!stateMatches) {
      return new Response(translate(requestLocale(), 'oauthCallbackInvalid'), {
        status: 400,
      })
    }
    await clearFailedAuthorization(flow)
    if (popupReauth) {
      return popupAuthorizationResponse({
        state: flowState,
        returnTo: flowReturnTo,
        result:
          url.searchParams.get('error') === 'access_denied'
            ? 'cancelled'
            : 'error',
      })
    }
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
      if (popupReauth) {
        return popupAuthorizationResponse({
          state: flowState,
          returnTo: flowReturnTo,
          result: error.oauthError === 'access_denied' ? 'cancelled' : 'error',
        })
      }
      return authorizationFailureResponse(request, error.oauthError, error.message)
    }
    throw error
  }

  const authorization = await useAuthorizationSession()
  const mode = flow.data.mode === 'reauth' ? 'reauth' : 'signin'
  const switchingAccount =
    mode === 'signin' &&
    (flow.data as SelectAccountFlow).select_account === true
  const returnTo = flowReturnTo
  if (mode === 'reauth') {
    // A reauthentication strengthens the account that is already signed in.
    // It must never replace that account with whichever subject the provider
    // happens to return for the login hint.
    const existingSubject =
      tokenSubject(authorization.data.id_token) ??
      tokenSubject(authorization.data.access_token)
    const grantedSubject =
      tokenSubject(tokens.id_token) ?? tokenSubject(tokens.access_token)
    if (
      !existingSubject ||
      !grantedSubject ||
      !constantTimeEqual(existingSubject, grantedSubject)
    ) {
      await clearFailedAuthorization(flow)
      if (popupReauth) {
        return popupAuthorizationResponse({
          state: flowState,
          returnTo: flowReturnTo,
          result: 'error',
        })
      }
      return authorizationFailureResponse(
        request,
        'invalid_request',
        translate(requestLocale(), 'accountAuthenticationRequired'),
      )
    }
    await authorization.update({
      elevated_access_token: tokens.access_token,
      elevated_expires_at: Date.now() + tokens.expires_in * 1000,
    })
    if (returnTo !== PASSWORD_CHANGE_CONTINUATION) {
      await storeAccountFlash({ message: 'reauthenticated' })
    }
  } else {
    // The previous account stays usable until the new grant succeeds. Only
    // then is the old account's elevated access and account-specific UI state
    // cleared, so a canceled or failed switch cannot destroy it first.
    if (switchingAccount) {
      await (await useMfaUiSession()).clear()
      await (await useAccountFlashSession()).clear()
    }
    await authorization.update({
      ...toStoredTokens(tokens),
      ...(switchingAccount
        ? {
            elevated_access_token: undefined,
            elevated_expires_at: undefined,
          }
        : {}),
    })
  }
  await flow.clear()

  if (popupReauth) {
    return popupAuthorizationResponse({
      state: flowState,
      returnTo: flowReturnTo,
      result: 'success',
    })
  }

  const response = redirect(new URL(returnTo, loadApplicationUrl()))
  // The callback is the only sign-in path that never touches the login
  // transport. Without this, a browser whose provider session answered the
  // authorization silently would return with tokens but no session for the
  // interactions that read one (the device verification, the consent page).
  const sessionId = mode === 'reauth' ? undefined : providerSessionId(tokens)
  const sessionCookie = sessionId ? providerSessionCookie(sessionId) : undefined
  if (sessionCookie) response.headers.append('set-cookie', sessionCookie)
  return response
}

/**
 * Provider session the authorization belongs to, taken from the `sid` claim.
 *
 * The ID Token carries the protected session id there — the same form the
 * login API returns in `sessions` — and the token comes straight from the
 * token endpoint over TLS, which is the trust the freshness checks below
 * already rely on.
 */
function providerSessionId(tokens: TokenResponse) {
  return sidClaim(tokens.id_token) ?? sidClaim(tokens.access_token)
}

function sidClaim(token: string | undefined) {
  const sid = tokenClaims(token)?.sid
  return typeof sid === 'string' && sid.length > 0 ? sid : undefined
}

export function tokenSubject(token: string | undefined) {
  const subject = tokenClaims(token)?.sub
  return typeof subject === 'string' && subject.length > 0
    ? subject
    : undefined
}

function tokenClaims(token: string | undefined) {
  if (!token) return
  const encodedPayload = token.split('.')[1]
  if (!encodedPayload) return
  try {
    return JSON.parse(
      Buffer.from(encodedPayload, 'base64url').toString('utf8'),
    ) as Record<string, unknown>
  } catch {
    return
  }
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
  // An unsuccessful popup attempt does not withdraw earlier authorization.
  // Keep its sealed retry parameters until success, replacement, or cookie expiry.
  if (flow.data.mode === 'reauth' && flow.data.popup) return
  const mode = flow.data.mode === 'reauth' ? 'reauth' : 'signin'
  const switchingAccount =
    mode === 'signin' &&
    (flow.data as SelectAccountFlow).select_account === true
  await flow.clear()
  if (switchingAccount) {
    // A canceled or failed switch leaves the previous account exactly as it
    // was: the new grant never replaced it, so nothing is withdrawn here.
    return
  }
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
  emitEvent('logout.local.result', { outcome: 'success', category: 'audit' })
  const authorization = await useAuthorizationSession()
  const idToken =
    typeof authorization.data.id_token === 'string'
      ? authorization.data.id_token
      : undefined
  const oauthClient = await loadOAuthClient()
  await authorization.clear()
  await (await useMfaUiSession()).clear()
  await (await useAccountFlashSession()).clear()
  const logoutUrl = providerLogoutUrl(
    applicationUrl,
    oauthClient.client_id,
    idToken,
  )
  return new Response(null, {
    status: 303,
    headers: { location: logoutUrl.toString() },
  })
}

export function providerLogoutUrl(
  applicationUrl: string,
  clientId: string,
  idToken?: string,
) {
  const logoutUrl = new URL('/oauth2/logout', publicIdentityApiUrl())
  const parameters = new URLSearchParams({
    client_id: clientId,
    post_logout_redirect_uri: new URL('/logout', applicationUrl).toString(),
  })
  if (idToken) parameters.set('id_token_hint', idToken)
  logoutUrl.search = parameters.toString()
  return logoutUrl
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
    totpEnabled: session.data.totp_enabled,
    enrollment: session.data.mfa_enrollment,
    recoveryCodes: session.data.regenerated_recovery_codes,
  }
}

export async function storeTotpEnabled(enabled: boolean) {
  await (await useMfaUiSession()).update({
    totp_enabled: enabled,
  })
}

export async function completeTotpStateChange(enabled: boolean) {
  await (await useMfaUiSession()).update({
    totp_enabled: enabled,
    mfa_enrollment: undefined,
    regenerated_recovery_codes: undefined,
  })
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
    if (error instanceof OAuthTokenExchangeError) {
      await clearAuthorizationCookie()
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
  if (pending) {
    // Diagnostic detail only: the caller waits on the single real exchange.
    console.debug('oauth token exchange merged with an in-flight exchange')
    return withSpan(
      'token.exchange.wait',
      'internal',
      { 'oauth.grant_type': body.get('grant_type') ?? 'unknown' },
      async () => pending,
    )
  }

  // Exactly one real execution span and one event per authorization code
  // exchange, even when several requests are merged onto it.
  const exchange = withSpan(
    'token.exchange',
    'internal',
    { 'oauth.grant_type': body.get('grant_type') ?? 'unknown' },
    async () => {
      const result = await performTokenExchange(body, clientId, clientSecret)
      emitEvent('token.exchange.observed', {
        outcome: 'success',
        attributes: { 'oauth.grant_type': body.get('grant_type') ?? 'unknown' },
      })
      return result
    },
  ).catch((error: unknown) => {
    const reason =
      error instanceof OAuthTokenExchangeError
        ? error.oauthError ?? 'exchange_failed'
        : 'system_error'
    emitEvent('token.exchange.observed', {
      outcome: 'rejected',
      reason,
      severity: error instanceof OAuthTokenExchangeError ? 'info' : 'error',
      attributes: { 'oauth.grant_type': body.get('grant_type') ?? 'unknown' },
    })
    throw error
  })
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
  const response = await fetchWithSpan(
    new URL('/oauth2/token', backchannelIdentityApiUrl()),
    {
      method: 'POST',
      headers: forwardRequestContext(new Headers({
        accept: 'application/json',
        authorization: `Basic ${Buffer.from(`${clientId}:${clientSecret}`).toString('base64')}`,
        'content-type': 'application/x-www-form-urlencoded',
      })),
      body,
    },
  )
  const payload = (await response.json().catch(() => null)) as
    | TokenResponse
    | TokenErrorResponse
    | null
  if (!response.ok || !payload || !('access_token' in payload)) {
    const grant = body.get('grant_type') ?? 'unknown grant'
    const oauthError = payload && 'error' in payload ? payload.error?.trim() : undefined
    const description =
      payload && 'error_description' in payload
        ? payload.error_description?.trim()
        : undefined
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

/**
 * A tiny no-store document that answers the account-center popup. The target
 * origin is the configured Login application origin, never a caller-supplied
 * value, and the payload contains no tokens or credentials.
 */
function popupAuthorizationResponse(input: {
  state: string
  returnTo: string
  result: AccountReauthResult
}) {
  const targetOrigin = new URL(loadApplicationUrl()).origin
  const message: AccountReauthMessage = {
    type: ACCOUNT_REAUTH_MESSAGE_TYPE,
    state: input.state,
    returnTo: input.returnTo,
    result: input.result,
  }
  const nonce = randomBytes(16).toString('base64url')
  const payload = JSON.stringify(message)
    .replaceAll('<', '\\u003c')
    .replaceAll('\u2028', '\\u2028')
    .replaceAll('\u2029', '\\u2029')
  // When a popup cannot open, the explicit top-level fallback reaches this same document. In
  // that case it resumes the safe continuation instead of leaving a blank page.
  const fallback =
    input.result === 'success' ? input.returnTo : '/account/security'
    const html = `<!doctype html><html><head><meta charset="utf-8"><meta name="robots" content="noindex"><title>Identity</title></head><body><script nonce="${nonce}">(()=>{const message=${payload};if(window.opener&&!window.opener.closed){window.opener.postMessage(message,${JSON.stringify(targetOrigin)})}else{window.location.replace(${JSON.stringify(fallback)})}})()</script></body></html>`
  return new Response(html, {
    status: 200,
    headers: {
      'cache-control': 'no-store',
      pragma: 'no-cache',
      'content-type': 'text/html; charset=utf-8',
      'content-security-policy': `default-src 'none'; script-src 'nonce-${nonce}'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'`,
      'referrer-policy': 'no-referrer',
      'x-content-type-options': 'nosniff',
      // Observability reads the completed popup result without parsing HTML.
      'x-identity-reauth-result': input.result,
    },
  })
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
