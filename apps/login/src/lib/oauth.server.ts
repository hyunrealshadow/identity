import {
  createHash,
  randomBytes,
  timingSafeEqual,
} from 'node:crypto'
import {
  getRequestHeader,
  setResponseHeader,
} from '@tanstack/react-start/server'

import { loadClientCredentials } from './client-credentials.server'

const API_URL = process.env.IDENTITY_API_URL ?? 'https://localhost:5150'
const AUTH_COOKIE = '__Host-identity.account'
const FLOW_COOKIE = '__Host-identity.oauth'
const API_RESOURCE = 'urn:identity:graphql'
const SCOPES =
  'openid profile email offline_access account session password.change'

interface OAuthFlow {
  state: string
  verifier: string
}

interface OAuthTokens {
  access_token: string
  refresh_token?: string
  expires_at: number
}

interface TokenResponse {
  access_token: string
  refresh_token?: string
  expires_in: number
}

export async function startAuthorization() {
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
    scope: SCOPES,
    resource: API_RESOURCE,
    state,
    code_challenge: challenge,
    code_challenge_method: 'S256',
  }).toString()

  return redirect(authorizeUrl, [
    serializeCookie(FLOW_COOKIE, { state, verifier } satisfies OAuthFlow, 600),
  ])
}

export async function finishAuthorization(request: Request) {
  const url = new URL(request.url)
  const code = url.searchParams.get('code')
  const returnedState = url.searchParams.get('state')
  const flow = readJsonCookie<OAuthFlow>(
    request.headers.get('cookie'),
    FLOW_COOKIE,
  )
  if (
    !code ||
    !returnedState ||
    !flow ||
    !constantTimeEqual(returnedState, flow.state)
  ) {
    return new Response('Invalid OAuth callback state', { status: 400 })
  }

  const credentials = await loadClientCredentials()
  const tokens = await exchangeToken(
    new URLSearchParams({
      grant_type: 'authorization_code',
      code,
      redirect_uri: callbackUrl(credentials.application_url),
      code_verifier: flow.verifier,
    }),
    credentials.client_id,
    credentials.client_secret,
  )

  return redirect(new URL('/', credentials.application_url), [
    clearCookie(FLOW_COOKIE),
    serializeCookie(AUTH_COOKIE, toStoredTokens(tokens), 30 * 24 * 60 * 60),
  ])
}

export function clearAuthorizationCookie() {
  setResponseHeader('set-cookie', clearCookie(AUTH_COOKIE))
}

export function finishLogout(applicationUrl: string) {
  return new Response(null, {
    status: 303,
    headers: {
      location: new URL('/', applicationUrl).toString(),
      'set-cookie': clearCookie(AUTH_COOKIE),
    },
  })
}

export async function accessToken() {
  const stored = readJsonCookie<OAuthTokens>(
    getRequestHeader('cookie'),
    AUTH_COOKIE,
  )
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
  })
  setResponseHeader(
    'set-cookie',
    serializeCookie(AUTH_COOKIE, next, 30 * 24 * 60 * 60),
  )
  return next.access_token
}

function toStoredTokens(tokens: TokenResponse): OAuthTokens {
  return {
    access_token: tokens.access_token,
    refresh_token: tokens.refresh_token,
    expires_at: Date.now() + tokens.expires_in * 1000,
  }
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

function redirect(location: URL, cookies: Array<string>) {
  const headers = new Headers({ location: location.toString() })
  for (const cookie of cookies) headers.append('set-cookie', cookie)
  return new Response(null, { status: 302, headers })
}

function serializeCookie(name: string, value: unknown, maxAge: number) {
  return `${name}=${encodeURIComponent(JSON.stringify(value))}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=${maxAge}`
}

function clearCookie(name: string) {
  return `${name}=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0`
}

function readJsonCookie<T>(
  cookieHeader: string | null | undefined,
  name: string,
): T | undefined {
  const encoded = cookieHeader
    ?.split(/;\s*/)
    .find((part) => part.startsWith(`${name}=`))
    ?.slice(name.length + 1)
  if (!encoded) return
  try {
    return JSON.parse(decodeURIComponent(encoded)) as T
  } catch {
    return
  }
}

function constantTimeEqual(left: string, right: string) {
  const leftBytes = Buffer.from(left)
  const rightBytes = Buffer.from(right)
  return (
    leftBytes.length === rightBytes.length &&
    timingSafeEqual(leftBytes, rightBytes)
  )
}
