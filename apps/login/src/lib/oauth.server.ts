import { createHash, randomBytes, timingSafeEqual } from 'node:crypto'

import { loadClientCredentials } from './client-credentials.server'
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

const API_URL = process.env.IDENTITY_API_URL ?? 'https://localhost:5150'
const API_RESOURCE = 'urn:identity:graphql'
const SCOPES =
  'openid profile email offline_access account session password.change'
const REAUTHENTICATION_SCOPES = {
  password: 'openid password.change',
  account: 'openid account.update',
  mfa: 'openid account.update',
} as const
const ACR_PASSWORD = 'urn:oasis:names:tc:SAML:2.0:ac:classes:Password'
const ACR_MFA = 'urn:identity:acr:mfa'

interface TokenResponse {
  access_token: string
  refresh_token?: string
  id_token?: string
  expires_in: number
}

export async function startAuthorization() {
  return startAuthorizationFlow('signin', '/')
}

export async function startReauthorization(
  returnTo: string | undefined,
  purpose: 'password' | 'account' | 'mfa' = 'password',
) {
  return startAuthorizationFlow(
    'reauth',
    safeReturnTo(returnTo, '/?message=reauthenticated'),
    purpose,
  )
}

async function startAuthorizationFlow(
  mode: OAuthFlowSession['mode'],
  returnTo: string,
  reauthPurpose: 'password' | 'account' | 'mfa' = 'password',
) {
  const credentials = await loadClientCredentials()
  const state = randomBytes(32).toString('base64url')
  const verifier = randomBytes(48).toString('base64url')
  const challenge = createHash('sha256').update(verifier).digest('base64url')
  const redirectUri = callbackUrl(credentials.application_url)
  const authorizeUrl = new URL('/oauth2/authorize', API_URL)
  authorizeUrl.search = new URLSearchParams({
    response_type: 'code',
    client_id: credentials.client_id,
    redirect_uri: redirectUri,
    scope:
      mode === 'reauth'
        ? REAUTHENTICATION_SCOPES[reauthPurpose]
        : SCOPES,
    resource: API_RESOURCE,
    state,
    code_challenge: challenge,
    code_challenge_method: 'S256',
  }).toString()
  if (mode === 'reauth') {
    authorizeUrl.searchParams.set('prompt', 'login')
    authorizeUrl.searchParams.set('max_age', '0')
    authorizeUrl.searchParams.set(
      'acr_values',
      reauthPurpose === 'mfa' ? ACR_MFA : ACR_PASSWORD,
    )
  }

  const flow = await useOAuthFlowSession()
  await flow.update({
    state,
    verifier,
    mode,
    return_to: returnTo,
    reauth_purpose: mode === 'reauth' ? reauthPurpose : undefined,
  } satisfies OAuthFlowSession)

  return redirect(authorizeUrl)
}

export async function finishAuthorization(request: Request) {
  const url = new URL(request.url)
  const code = url.searchParams.get('code')
  const returnedState = url.searchParams.get('state')
  const flow = await useOAuthFlowSession()
  if (
    !code ||
    !returnedState ||
    typeof flow.data.state !== 'string' ||
    typeof flow.data.verifier !== 'string' ||
    !constantTimeEqual(returnedState, flow.data.state)
  ) {
    return new Response(translate(requestLocale(), 'oauthCallbackInvalid'), {
      status: 400,
    })
  }

  const credentials = await loadClientCredentials()
  const tokens = await exchangeToken(
    new URLSearchParams({
      grant_type: 'authorization_code',
      code,
      redirect_uri: callbackUrl(credentials.application_url),
      code_verifier: flow.data.verifier,
    }),
    credentials.client_id,
    credentials.client_secret,
  )

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

  return redirect(new URL(returnTo, credentials.application_url))
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
    recoveryCodes: session.data.recovery_codes,
  }
}

export async function storeMfaEnrollment(enrollment: {
  secret: string
  otpauth_uri: string
  enrollment_token: string
}) {
  await (await useMfaUiSession()).update({
    mfa_enrollment: enrollment,
    recovery_codes: undefined,
  })
}

export async function storeRecoveryCodes(recoveryCodes: Array<string>) {
  await (await useMfaUiSession()).update({
    mfa_enrollment: undefined,
    recovery_codes: recoveryCodes,
  })
}

export async function clearMfaUiState() {
  await (await useMfaUiSession()).update({
    mfa_enrollment: undefined,
    recovery_codes: undefined,
  })
}

export async function accessToken() {
  const session = await useAuthorizationSession()
  const stored = storedTokens(session.data)
  if (!stored) return
  if (stored.expires_at > Date.now() + 30_000) return stored.access_token
  if (!stored.refresh_token) return

  const credentials = await loadClientCredentials()
  const refreshed = await exchangeToken(
    new URLSearchParams({
      grant_type: 'refresh_token',
      refresh_token: stored.refresh_token,
    }),
    credentials.client_id,
    credentials.client_secret,
  )
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

async function exchangeToken(
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
    | { error?: string }
    | null
  if (!response.ok || !payload || !('access_token' in payload)) {
    throw new Error(
      payload && 'error' in payload
        ? `OAuth token exchange failed: ${payload.error}`
        : `OAuth token exchange failed (${response.status})`,
    )
  }
  return payload
}

function callbackUrl(applicationUrl: string) {
  return new URL('/oauth/callback', applicationUrl).toString()
}

function safeReturnTo(value: string | undefined, fallback: string) {
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
