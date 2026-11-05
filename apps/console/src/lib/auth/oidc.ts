import * as oauth from 'oauth4webapi'

import { sanitizeReturnTo } from '#/lib/auth/return-to'
import {
  AuthError,
  POPUP_STATE_PREFIX,
  buildTransaction,
  saveTransaction,
  type AuthErrorCode,
  type AuthTransaction,
} from '#/lib/auth/transaction'
import type { AuthSession, IdTokenClaims } from '#/lib/auth/session'
import type { RuntimeConfig } from '#/lib/config'
import type { Locale } from '#/lib/i18n'

export const GRAPHQL_RESOURCE = 'urn:identity:graphql'

export interface StepUpRequest {
  acrValues?: string
  maxAge?: number
  requiredScopes?: string[]
}

export interface BeginAuthorizationOptions {
  config: RuntimeConfig
  locale: Locale
  returnTo: string
  stepUp?: StepUpRequest
  /**
   * Default assurance for an ordinary sign-in. A step-up request always takes
   * precedence. This never adds scopes and never forces a recent authentication
   * window unless `stepUp.maxAge` is explicitly set.
   */
  acrValues?: string
  /**
   * Routing hint for an explicit reauthentication or step-up. It identifies the
   * current account but is not proof of identity; `expectedSubject` provides
   * the binding checked after the callback token is validated.
   */
  loginHint?: string
  /** Normalized subject the callback must match for an explicit step-up. */
  expectedSubject?: string
  /**
   * Explicit account selection for a normal sign-in. It always asks the
   * provider with `prompt=select_account` and never carries a prior-user hint
   * or a subject binding. It cannot be combined with `stepUp`.
   */
  selectAccount?: boolean
  /** Invoked after the transaction is saved and before navigation. */
  beforeRedirect?: (request: AuthorizationRequest) => void
  /**
   * Return the request to the caller instead of navigating. The parent owns
   * the transaction in memory; it is deliberately not stored in sessionStorage
   * because the callback runs in a separate popup browsing context.
   */
  deferNavigation?: boolean
  fetchImpl?: typeof fetch
}

export interface AuthorizationRequest {
  url: string
  transaction: AuthTransaction
  discovery: oauth.AuthorizationServer
}

function fetchOptions(fetchImpl?: typeof fetch) {
  return fetchImpl ? { [oauth.customFetch]: fetchImpl } : undefined
}

function client(config: RuntimeConfig): oauth.Client {
  return { client_id: config.clientId }
}

/** Map an authorization error response (RFC 6749 §4.1.2.1) to a local code. */
function authorizationErrorCode(error: string): AuthErrorCode {
  switch (error) {
    case 'access_denied':
      return 'authorization_denied'
    case 'unmet_authentication_requirements':
      return 'authentication_requirements_unmet'
    default:
      return 'authorization_failed'
  }
}

export async function discoverAuthorizationServer(
  config: RuntimeConfig,
  fetchImpl?: typeof fetch,
): Promise<oauth.AuthorizationServer> {
  const issuer = new URL(config.issuer)

  let response: Response
  try {
    response = await oauth.discoveryRequest(issuer, fetchOptions(fetchImpl))
  } catch (error) {
    throw new AuthError('discovery_failed', { cause: error })
  }

  let discovery: oauth.AuthorizationServer
  try {
    discovery = await oauth.processDiscoveryResponse(issuer, response)
  } catch (error) {
    throw new AuthError('discovery_failed', { cause: error })
  }

  if (discovery.issuer !== config.issuer) throw new AuthError('issuer_mismatch')
  if (!discovery.authorization_endpoint || !discovery.token_endpoint) {
    throw new AuthError('discovery_failed')
  }
  return discovery
}

export async function createAuthorizationRequest(
  options: BeginAuthorizationOptions,
): Promise<AuthorizationRequest> {
  if (options.selectAccount && options.stepUp) {
    // Selection is a different-account transition. Combining it with a step-up
    // would drop the subject binding, so reject the request instead.
    throw new AuthError('invalid_transaction')
  }

  const discovery = await discoverAuthorizationServer(
    options.config,
    options.fetchImpl,
  )
  const state = `${options.deferNavigation ? POPUP_STATE_PREFIX : ''}${oauth.generateRandomState()}`
  const nonce = oauth.generateRandomNonce()
  const codeVerifier = oauth.generateRandomCodeVerifier()
  const codeChallenge = await oauth.calculatePKCECodeChallenge(codeVerifier)

  const acrValues = options.stepUp?.acrValues ?? options.acrValues
  const maxAge = options.stepUp?.maxAge
  // Hints and identity binding belong only to explicit reauthentication so an
  // ordinary login can never inherit them from a lingering in-memory session.
  const loginHint = options.stepUp ? options.loginHint : undefined
  const expectedSubject = options.stepUp ? options.expectedSubject : undefined
  // Account selection is explicit and only for a normal sign-in. A step-up is
  // rejected above, so these two request shapes can never be merged.
  const selectAccount = options.selectAccount === true

  const transaction = buildTransaction({
    state,
    nonce,
    codeVerifier,
    locale: options.locale,
    returnTo: sanitizeReturnTo(options.returnTo),
    acrValues,
    maxAge,
    expectedSubject,
  })

  const url = new URL(discovery.authorization_endpoint as string)
  url.searchParams.set('client_id', options.config.clientId)
  url.searchParams.set('redirect_uri', options.config.redirectUri)
  url.searchParams.set('response_type', 'code')
  url.searchParams.set('scope', options.config.scope)
  url.searchParams.set('code_challenge', codeChallenge)
  url.searchParams.set('code_challenge_method', 'S256')
  url.searchParams.set('state', state)
  url.searchParams.set('nonce', nonce)
  url.searchParams.set('resource', GRAPHQL_RESOURCE)
  url.searchParams.set('ui_locales', options.locale)

  if (acrValues) {
    url.searchParams.set('acr_values', acrValues)
  }
  if (maxAge !== undefined) {
    url.searchParams.set('max_age', String(maxAge))
  }
  if (loginHint) {
    url.searchParams.set('login_hint', loginHint)
  }
  if (selectAccount) {
    url.searchParams.set('prompt', 'select_account')
  }

  return { url: url.toString(), transaction, discovery }
}

export async function beginAuthorization(
  options: BeginAuthorizationOptions,
): Promise<AuthorizationRequest | undefined> {
  const request = await createAuthorizationRequest(options)
  if (options.deferNavigation) {
    // The parent retains the transaction in memory. Nothing is stored in
    // sessionStorage and no navigation happens in this browsing context.
    return request
  }
  try {
    saveTransaction(request.transaction)
  } catch (error) {
    throw new AuthError('invalid_transaction', { cause: error })
  }
  try {
    options.beforeRedirect?.(request)
  } catch {
    // The marker is advisory loop protection. A storage or listener failure
    // must not prevent the validated authorization request from continuing.
  }
  window.location.assign(request.url)
  return request
}

function audienceIncludes(
  audience: string | string[] | undefined,
  clientId: string,
): boolean {
  if (typeof audience === 'string') return audience === clientId
  return Array.isArray(audience) && audience.includes(clientId)
}

function normalizeClaims(
  claims: oauth.IDToken,
  config: RuntimeConfig,
  issuer: string,
): IdTokenClaims {
  if (claims.iss !== issuer) throw new AuthError('issuer_mismatch')
  if (!audienceIncludes(claims.aud, config.clientId))
    throw new AuthError('claims_invalid')
  if (typeof claims.sub !== 'string' || !claims.sub)
    throw new AuthError('claims_invalid')
  if (typeof claims.exp !== 'number' || claims.exp * 1000 <= Date.now()) {
    throw new AuthError('claims_invalid')
  }

  const result: IdTokenClaims = {
    sub: claims.sub,
    iss: claims.iss,
    aud: claims.aud as string | string[],
    exp: claims.exp,
  }
  if (typeof claims.iat === 'number') result.iat = claims.iat
  if (typeof claims.auth_time === 'number') result.auth_time = claims.auth_time
  if (typeof claims.acr === 'string') result.acr = claims.acr
  if (Array.isArray(claims.amr))
    result.amr = claims.amr.filter((entry) => typeof entry === 'string')
  for (const key of [
    'name',
    'preferred_username',
    'email',
    'given_name',
    'family_name',
    'nickname',
    'picture',
    'locale',
    'zoneinfo',
  ] as const) {
    const value = claims[key]
    if (typeof value === 'string') result[key] = value
  }
  if (typeof claims.email_verified === 'boolean')
    result.email_verified = claims.email_verified
  return result
}

export async function completeAuthorization(input: {
  config: RuntimeConfig
  callbackUrl: string
  transaction: AuthTransaction
  fetchImpl?: typeof fetch
}): Promise<AuthSession> {
  const callback = new URL(input.callbackUrl)
  const redirect = new URL(input.config.redirectUri)

  if (
    callback.origin !== redirect.origin ||
    callback.pathname !== redirect.pathname
  ) {
    throw new AuthError('callback_mismatch')
  }
  const state = callback.searchParams.get('state')
  if (!state || state !== input.transaction.state)
    throw new AuthError('state_mismatch')
  const authorizationError = callback.searchParams.get('error')
  if (authorizationError) {
    throw new AuthError(authorizationErrorCode(authorizationError))
  }

  const discovery = await discoverAuthorizationServer(
    input.config,
    input.fetchImpl,
  )
  const clientMetadata = client(input.config)

  let parameters: URLSearchParams
  try {
    parameters = oauth.validateAuthResponse(
      discovery,
      clientMetadata,
      callback,
      input.transaction.state,
    )
  } catch (error) {
    throw new AuthError('exchange_failed', { cause: error })
  }

  const responseIssuer = parameters.get('iss')
  if (responseIssuer && responseIssuer !== discovery.issuer) {
    throw new AuthError('issuer_mismatch')
  }

  let response: Response
  try {
    response = await oauth.authorizationCodeGrantRequest(
      discovery,
      clientMetadata,
      oauth.None(),
      parameters,
      input.config.redirectUri,
      input.transaction.codeVerifier,
      fetchOptions(input.fetchImpl),
    )
  } catch (error) {
    throw new AuthError('exchange_failed', { cause: error })
  }

  let tokens: oauth.TokenEndpointResponse
  try {
    const processOptions: oauth.ProcessAuthorizationCodeResponseOptions = {
      expectedNonce: input.transaction.nonce,
      requireIdToken: true,
    }
    // oauth4webapi only validates auth_time when maxAge is present. A callback
    // whose request omitted max_age therefore stays compatible, while an
    // automatic max_age=0 request requires a present and fresh auth_time.
    if (input.transaction.maxAge !== undefined) {
      processOptions.maxAge = input.transaction.maxAge
    }
    tokens = await oauth.processAuthorizationCodeResponse(
      discovery,
      clientMetadata,
      response,
      processOptions,
    )
  } catch (error) {
    throw new AuthError('exchange_failed', { cause: error })
  }

  try {
    await oauth.validateApplicationLevelSignature(discovery, response)
  } catch (error) {
    throw new AuthError('claims_invalid', { cause: error })
  }

  const claims = oauth.getValidatedIdTokenClaims(tokens)
  if (!claims) throw new AuthError('claims_invalid')

  if (tokens.token_type !== 'bearer')
    throw new AuthError('token_response_invalid')
  if (typeof tokens.access_token !== 'string' || !tokens.access_token) {
    throw new AuthError('token_response_invalid')
  }
  if (
    typeof tokens.expires_in !== 'number' ||
    !Number.isFinite(tokens.expires_in) ||
    tokens.expires_in <= 0
  ) {
    throw new AuthError('token_response_invalid')
  }

  const normalizedClaims = normalizeClaims(
    claims,
    input.config,
    discovery.issuer,
  )
  // Identity binding is checked only after the ID token signature has been
  // validated, using the same normalized subject that will be stored.
  if (
    input.transaction.expectedSubject !== undefined &&
    normalizedClaims.sub !== input.transaction.expectedSubject
  ) {
    throw new AuthError('claims_invalid')
  }
  const expiresAt = Math.min(
    Date.now() + tokens.expires_in * 1000,
    normalizedClaims.exp * 1000,
  )
  const scope = tokens.scope ?? input.config.scope
  const grantedScopes = scope.split(/\s+/).filter(Boolean)

  return {
    accessToken: tokens.access_token,
    idToken: tokens.id_token ?? '',
    expiresAt,
    scope,
    grantedScopes,
    claims: normalizedClaims,
    endSessionEndpoint: discovery.end_session_endpoint,
  }
}

export function buildEndSessionUrl(input: {
  config: RuntimeConfig
  endpoint: string
  idToken: string
}): string {
  let endpoint: URL
  try {
    endpoint = new URL(input.endpoint)
  } catch (error) {
    throw new AuthError('missing_end_session', { cause: error })
  }
  if (endpoint.protocol !== 'https:' && endpoint.protocol !== 'http:') {
    throw new AuthError('missing_end_session')
  }
  if (endpoint.username || endpoint.password)
    throw new AuthError('missing_end_session')
  if (!input.idToken) throw new AuthError('missing_end_session')

  endpoint.searchParams.set('id_token_hint', input.idToken)
  endpoint.searchParams.set('client_id', input.config.clientId)
  endpoint.searchParams.set(
    'post_logout_redirect_uri',
    input.config.postLogoutRedirectUri,
  )
  return endpoint.toString()
}
