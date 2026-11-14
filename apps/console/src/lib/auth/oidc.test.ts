// @vitest-environment node
import { webcrypto } from 'node:crypto'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

import {
  beginAuthorization,
  completeAuthorization,
  createAuthorizationRequest,
} from './oidc'
import { buildTransaction } from './transaction'
import type { RuntimeConfig } from '#/lib/config'

const mocks = vi.hoisted(() => ({
  validateAuthResponse: vi.fn(),
  authorizationCodeGrantRequest: vi.fn(),
  processAuthorizationCodeResponse: vi.fn(),
  validateApplicationLevelSignature: vi.fn(),
  getValidatedIdTokenClaims: vi.fn(),
}))

vi.mock('oauth4webapi', async (importOriginal) => {
  const actual = await importOriginal<typeof import('oauth4webapi')>()
  return {
    ...actual,
    validateAuthResponse: mocks.validateAuthResponse,
    authorizationCodeGrantRequest: mocks.authorizationCodeGrantRequest,
    processAuthorizationCodeResponse: mocks.processAuthorizationCodeResponse,
    validateApplicationLevelSignature: mocks.validateApplicationLevelSignature,
    getValidatedIdTokenClaims: mocks.getValidatedIdTokenClaims,
  }
})

const config: RuntimeConfig = {
  issuer: 'https://issuer.example.test',
  graphqlUrl: 'https://issuer.example.test/graphql',
  clientId: 'console',
  redirectUri: 'https://console.example.test/callback',
  postLogoutRedirectUri: 'https://console.example.test/logout',
  accountUrl: 'https://account.example.test',
  scope: 'openid profile email management.user.read',
  displayName: 'Identity Console',
  environment: 'test',
}

function discoveryFetch(): typeof fetch {
  return vi.fn<typeof fetch>().mockImplementation(() =>
    Promise.resolve(
      new Response(
        JSON.stringify({
          issuer: config.issuer,
          authorization_endpoint: `${config.issuer}/authorize`,
          token_endpoint: `${config.issuer}/token`,
          end_session_endpoint: `${config.issuer}/logout`,
        }),
        { status: 200, headers: { 'Content-Type': 'application/json' } },
      ),
    ),
  )
}

function transaction(expectedSubject?: string) {
  return buildTransaction({
    state: 'state-a',
    nonce: 'nonce-a',
    codeVerifier: 'verifier-a',
    locale: 'en-US',
    returnTo: '/',
    expectedSubject,
  })
}

function tokenClaims(sub: string) {
  return {
    sub,
    iss: config.issuer,
    aud: config.clientId,
    exp: Math.floor(Date.now() / 1000) + 3_600,
  }
}

function callbackUrl() {
  return `${config.redirectUri}?state=state-a&code=code-a`
}

beforeEach(() => {
  vi.stubGlobal('crypto', webcrypto)
  vi.clearAllMocks()
  mocks.validateAuthResponse.mockReturnValue(new URLSearchParams('code=code-a'))
  mocks.authorizationCodeGrantRequest.mockResolvedValue(new Response('{}'))
  mocks.processAuthorizationCodeResponse.mockResolvedValue({
    access_token: 'access-token',
    id_token: 'id-token',
    token_type: 'bearer',
    expires_in: 3_600,
    scope: config.scope,
  })
  mocks.validateApplicationLevelSignature.mockResolvedValue(undefined)
})
afterEach(() => { vi.unstubAllGlobals() })

describe('authorization request', () => {
  it('uses fresh AAL2 with a login hint for reauthentication without adding scopes', async () => {
    const request = await createAuthorizationRequest({
      config,
      locale: 'zh-CN',
      returnTo: '/users?filter=a#section',
      stepUp: { acrValues: 'aal2', maxAge: 0, requiredScopes: ['management.user.update'] },
      loginHint: 'user-a',
      expectedSubject: 'user-a',
      fetchImpl: discoveryFetch(),
    })

    const url = new URL(request.url)
    expect(url.searchParams.get('scope')).toBe(config.scope)
    expect(url.searchParams.get('acr_values')).toBe('aal2')
    expect(url.searchParams.get('max_age')).toBe('0')
    expect(url.searchParams.get('login_hint')).toBe('user-a')
    expect(url.searchParams.get('prompt')).toBeNull()
    expect(url.searchParams.get('id_token_hint')).toBeNull()
    expect(url.searchParams.get('ui_locales')).toBe('zh-CN')
    expect(request.transaction.maxAge).toBe(0)
    expect(request.transaction.expectedSubject).toBe('user-a')
    expect(request.transaction.returnTo).toBe('/users?filter=a#section')
  })

  it('requests AAL2 for ordinary console sign-in without a prompt, hint or recent window', async () => {
    const request = await createAuthorizationRequest({
      config,
      locale: 'en-US',
      returnTo: '/',
      acrValues: 'aal2',
      fetchImpl: discoveryFetch(),
    })

    const url = new URL(request.url)
    expect(url.searchParams.get('scope')).toBe(config.scope)
    expect(url.searchParams.get('acr_values')).toBe('aal2')
    expect(url.searchParams.get('max_age')).toBeNull()
    expect(url.searchParams.get('prompt')).toBeNull()
    expect(url.searchParams.get('login_hint')).toBeNull()
    expect(url.searchParams.get('id_token_hint')).toBeNull()
    expect(request.transaction.maxAge).toBeUndefined()
    expect(request.transaction.expectedSubject).toBeUndefined()
  })

  it('ignores stray hints and subject binding when no step-up is requested', async () => {
    const request = await createAuthorizationRequest({
      config,
      locale: 'en-US',
      returnTo: '/',
      acrValues: 'aal2',
      loginHint: 'user-a',
      expectedSubject: 'user-a',
      fetchImpl: discoveryFetch(),
    })

    const url = new URL(request.url)
    expect(url.searchParams.get('max_age')).toBeNull()
    expect(url.searchParams.get('prompt')).toBeNull()
    expect(url.searchParams.get('login_hint')).toBeNull()
    expect(request.transaction.maxAge).toBeUndefined()
    expect(request.transaction.expectedSubject).toBeUndefined()
  })

  it('requests explicit account selection without a hint or subject binding', async () => {
    const request = await createAuthorizationRequest({
      config,
      locale: 'en-US',
      returnTo: '/users?filter=a',
      acrValues: 'aal2',
      selectAccount: true,
      loginHint: 'ignored-user',
      expectedSubject: 'ignored-user',
      fetchImpl: discoveryFetch(),
    })

    const url = new URL(request.url)
    expect(url.searchParams.get('prompt')).toBe('select_account')
    expect(url.searchParams.get('login_hint')).toBeNull()
    expect(url.searchParams.get('acr_values')).toBe('aal2')
    expect(url.searchParams.get('max_age')).toBeNull()
    expect(request.transaction.expectedSubject).toBeUndefined()
  })

  it('rejects account selection combined with a subject-bound step-up', async () => {
    await expect(
      createAuthorizationRequest({
        config,
        locale: 'en-US',
        returnTo: '/',
        selectAccount: true,
        stepUp: { acrValues: 'aal2', maxAge: 0 },
        loginHint: 'user-a',
        expectedSubject: 'user-a',
        fetchImpl: discoveryFetch(),
      }),
    ).rejects.toMatchObject({ code: 'invalid_transaction' })
  })

  it('returns a deferred request for the parent to retain without navigating', async () => {
    const request = await beginAuthorization({
      config,
      locale: 'en-US',
      returnTo: '/users',
      stepUp: { acrValues: 'aal2', maxAge: 0 },
      loginHint: 'user-a',
      expectedSubject: 'user-a',
      deferNavigation: true,
      fetchImpl: discoveryFetch(),
    })

    expect(request?.url).toContain('max_age=0')
    expect(request?.transaction.expectedSubject).toBe('user-a')
    expect(request?.transaction.returnTo).toBe('/users')
  })
})

describe('expected subject binding', () => {
  it('rejects a different normalized subject after token signature validation', async () => {
    mocks.getValidatedIdTokenClaims.mockReturnValue(tokenClaims('user-b'))

    await expect(
      completeAuthorization({
        config,
        callbackUrl: callbackUrl(),
        transaction: transaction('user-a'),
        fetchImpl: discoveryFetch(),
      }),
    ).rejects.toMatchObject({ code: 'claims_invalid' })

    expect(mocks.validateApplicationLevelSignature).toHaveBeenCalledTimes(1)
    expect(mocks.getValidatedIdTokenClaims).toHaveBeenCalledTimes(1)
  })

  it('accepts the same normalized subject and keeps it in the session claims', async () => {
    mocks.getValidatedIdTokenClaims.mockReturnValue(tokenClaims('user-a'))

    const session = await completeAuthorization({
      config,
      callbackUrl: callbackUrl(),
      transaction: transaction('user-a'),
      fetchImpl: discoveryFetch(),
    })

    expect(session.claims.sub).toBe('user-a')
  })

  it('does not impose subject binding when the transaction has none', async () => {
    mocks.getValidatedIdTokenClaims.mockReturnValue(tokenClaims('user-b'))

    const session = await completeAuthorization({
      config,
      callbackUrl: callbackUrl(),
      transaction: transaction(),
      fetchImpl: discoveryFetch(),
    })

    expect(session.claims.sub).toBe('user-b')
  })
})

describe('authorization error responses', () => {
  it.each([
    ['unmet_authentication_requirements', 'authentication_requirements_unmet'],
    ['access_denied', 'authorization_denied'],
    ['invalid_scope', 'scope_not_allowed'],
    ['server_error', 'authorization_failed'],
  ])('reports %s without attempting a code exchange', async (error, code) => {
    await expect(
      completeAuthorization({
        config,
        callbackUrl: `${config.redirectUri}?error=${error}&state=state-a`,
        transaction: transaction(),
        fetchImpl: discoveryFetch(),
      }),
    ).rejects.toMatchObject({ code })
    expect(mocks.authorizationCodeGrantRequest).not.toHaveBeenCalled()
  })

  it('rejects an error response for another transaction as a state mismatch', async () => {
    await expect(
      completeAuthorization({
        config,
        callbackUrl: `${config.redirectUri}?error=access_denied&state=state-b`,
        transaction: transaction(),
        fetchImpl: discoveryFetch(),
      }),
    ).rejects.toMatchObject({ code: 'state_mismatch' })
  })
})
