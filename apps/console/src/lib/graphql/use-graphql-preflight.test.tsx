import { act, render } from '@testing-library/react'
import { beforeEach, describe, expect, it, vi } from 'vitest'

import { AuthProvider, useAuth } from '#/lib/auth/context'
import { clearAuthSession, setAuthSession, type AuthSession } from '#/lib/auth/session'
import type { RuntimeConfig } from '#/lib/config'
import { LocaleProvider } from '#/lib/i18n'
import { RuntimeConfigProvider } from '#/lib/runtime-config'
import { useGraphQL } from '#/lib/graphql/use-graphql'
import type { GraphQLResult } from '#/lib/graphql/transport'

const mocks = vi.hoisted(() => ({
  beginAuthorization: vi.fn(),
}))

vi.mock('#/lib/auth/oidc', async (importOriginal) => {
  const actual = await importOriginal<typeof import('#/lib/auth/oidc')>()
  return {
    ...actual,
    beginAuthorization: mocks.beginAuthorization,
  }
})

const config: RuntimeConfig = {
  issuer: 'https://issuer.example.test',
  graphqlUrl: 'https://issuer.example.test/graphql',
  clientId: 'console',
  redirectUri: `${window.location.origin}/callback`,
  postLogoutRedirectUri: `${window.location.origin}/logout`,
  accountUrl: 'https://account.example.test',
  scope: 'openid profile email',
  displayName: 'Identity Console',
  environment: 'test',
}

function session(grantedScopes: string[] = ['openid', 'profile', 'email']): AuthSession {
  const now = Math.floor(Date.now() / 1_000)
  return {
    accessToken: 'access-token',
    idToken: 'id-token',
    expiresAt: Date.now() + 60_000,
    scope: config.scope,
    grantedScopes,
    claims: {
      sub: 'user-a',
      iss: config.issuer,
      aud: config.clientId,
      exp: now + 3_600,
    },
    endSessionEndpoint: `${config.issuer}/logout`,
  }
}

let requestApi: ReturnType<typeof useGraphQL> | undefined
let authApi: ReturnType<typeof useAuth> | undefined

function Probe() {
  requestApi = useGraphQL()
  authApi = useAuth()
  return null
}

function renderProbe() {
  return render(
    <RuntimeConfigProvider config={config}>
      <LocaleProvider>
        <AuthProvider>
          <Probe />
        </AuthProvider>
      </LocaleProvider>
    </RuntimeConfigProvider>,
  )
}

function challengeResponse() {
  return new Response(
    JSON.stringify({
      data: null,
      errors: [
        {
          message: 'challenge',
          extensions: {
            code: 'insufficient_user_authentication',
            acr_values: 'aal2',
            max_age: 0,
          },
        },
      ],
    }),
    {
      status: 401,
      headers: {
        'Content-Type': 'application/json',
        'WWW-Authenticate':
          'Bearer error="insufficient_user_authentication", acr_values="aal2", max_age="0"',
      },
    },
  )
}

beforeEach(() => {
  vi.restoreAllMocks()
  vi.unstubAllGlobals()
  clearAuthSession()
  window.sessionStorage.clear()
  mocks.beginAuthorization.mockReset().mockResolvedValue(undefined)
  requestApi = undefined
  authApi = undefined
})

describe('useGraphQL with generated access metadata', () => {
  it('blocks a management write before the network and without reauthentication', async () => {
    setAuthSession(session())
    const fetchMock = vi.fn<typeof fetch>()
    vi.stubGlobal('fetch', fetchMock)
    renderProbe()

    let result: GraphQLResult<unknown> | undefined
    await act(async () => {
      result = await requestApi?.(
        'mutation ConsoleDisableUser($input: UserStateInput!) { disableUser(input: $input) { userId } }',
        { input: { id: 'user-a', expectedVersion: 'version-a' } },
      )
    })

    expect(fetchMock).not.toHaveBeenCalled()
    expect(mocks.beginAuthorization).not.toHaveBeenCalled()
    expect(result?.forbidden).toBe(true)
    expect(result?.failure?.code).toBe('insufficient_scope')
    expect(result?.stepUp).toBeUndefined()
    expect(result?.requestId).toBeUndefined()
    expect(result?.traceId).toBeUndefined()
  })

  it('requires fresh AAL2 locally when scopes are present but claims are not', async () => {
    setAuthSession(session(['management.user.read']))
    const fetchMock = vi.fn<typeof fetch>().mockResolvedValue(new Response(JSON.stringify({ data: { effectivePermissions: { __typename: 'EffectivePermissions' } } }), { status: 200, headers: { 'Content-Type': 'application/json' } }))
    vi.stubGlobal('fetch', fetchMock)
    renderProbe()

    let result: GraphQLResult<unknown> | undefined
    await act(async () => {
      result = await requestApi?.(
        'query ConsoleUsers { users { edges { node { id } } } }',
        {},
      )
    })

    expect(fetchMock).toHaveBeenCalledOnce()
    expect(JSON.parse(fetchMock.mock.calls[0][1]!.body as string).query).toContain('query ConsoleAuthenticationCheck')
    expect(mocks.beginAuthorization).toHaveBeenCalledTimes(1)
    expect(mocks.beginAuthorization.mock.calls[0][0].stepUp).toEqual({
      acrValues: 'aal2',
      maxAge: 0,
    })
    expect(result?.stepUp?.source).toBe('preflight')
    expect(result?.failure?.code).toBe('insufficient_user_authentication')
    expect(result?.unauthorized).toBe(false)
  })

  it('sends a variable-dependent unknown decision to the backend', async () => {
    setAuthSession(session())
    const fetchMock = vi.fn<typeof fetch>().mockResolvedValue(challengeResponse())
    vi.stubGlobal('fetch', fetchMock)
    renderProbe()

    let result: GraphQLResult<unknown> | undefined
    await act(async () => {
      result = await requestApi?.(
        'query Q($include: Boolean!) { effectivePermissions @include(if: $include) { requestableScopes } }',
        {},
      )
    })

    expect(fetchMock).toHaveBeenCalledTimes(1)
    expect(result?.stepUp).toBeDefined()
    expect(mocks.beginAuthorization).toHaveBeenCalledTimes(1)
  })

  it('keeps the no-scope bootstrap on the network', async () => {
    setAuthSession(session())
    const fetchMock = vi.fn<typeof fetch>().mockResolvedValue(
      new Response(
        JSON.stringify({
          data: {
            effectivePermissions: { requestableScopes: [] },
            instanceInfo: { name: 'Identity' },
          },
          errors: [],
        }),
        { status: 200, headers: { 'Content-Type': 'application/json' } },
      ),
    )
    vi.stubGlobal('fetch', fetchMock)
    renderProbe()

    let result: GraphQLResult<unknown> | undefined
    await act(async () => {
      result = await requestApi?.(
        'query ConsoleBootstrap { effectivePermissions { requestableScopes } instanceInfo { name } }',
        {},
      )
    })

    expect(fetchMock).toHaveBeenCalledTimes(1)
    expect(result?.forbidden).toBe(false)
    expect(result?.failure).toBeUndefined()
    expect(authApi?.status).toBe('authenticated')
    expect(mocks.beginAuthorization).not.toHaveBeenCalled()
  })
})

it('uses ordinary sign-in when live session validation rejects a locally stale credential', async () => {
  setAuthSession(session(['management.user.read']))
  const open = vi.spyOn(window, 'open')
  const fetchMock = vi.fn<typeof fetch>().mockResolvedValue(new Response(JSON.stringify({
    data: null, errors: [{ message: 'Expired session', extensions: { code: 28109, kind: 'authentication_error' } }],
  }), { status: 401, headers: { 'Content-Type': 'application/json' } }))
  vi.stubGlobal('fetch', fetchMock)
  renderProbe()
  let result: GraphQLResult<unknown> | undefined
  await act(async () => { result = await requestApi?.('query ConsoleUsers { users { edges { node { id } } } }', {}) })
  expect(result?.unauthorized).toBe(true)
  expect(fetchMock).toHaveBeenCalledOnce()
  expect(mocks.beginAuthorization).toHaveBeenCalledOnce()
  expect(mocks.beginAuthorization.mock.calls[0][0].stepUp).toBeUndefined()
  expect(mocks.beginAuthorization.mock.calls[0][0].deferNavigation).toBeUndefined()
  expect(open).not.toHaveBeenCalled()
})

it('does not turn a live-session network failure into authentication recovery', async () => {
  setAuthSession(session(['management.user.read']))
  vi.stubGlobal('fetch', vi.fn().mockRejectedValue(new TypeError('Network unavailable')))
  renderProbe()
  let result: GraphQLResult<unknown> | undefined
  await act(async () => { result = await requestApi?.('query ConsoleUsers { users { edges { node { id } } } }', {}) })
  expect(result?.failure?.kind).toBe('network')
  expect(mocks.beginAuthorization).not.toHaveBeenCalled()
})
