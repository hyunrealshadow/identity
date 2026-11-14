import { act, render } from '@testing-library/react'
import { beforeEach, describe, expect, it, vi } from 'vitest'

import { AuthProvider, useAuth } from '#/lib/auth/context'
import {
  clearAuthSession,
  setAuthSession,
  type AuthSession,
} from '#/lib/auth/session'
import type { RuntimeConfig } from '#/lib/config'
import { LocaleProvider } from '#/lib/i18n'
import { RuntimeConfigProvider } from '#/lib/runtime-config'
import { RequestableAccessContext } from '#/lib/graphql/access-context'
import { getAuthSession } from '#/lib/auth/session'
import { useGraphQL } from '#/lib/graphql/use-graphql'
import type { GraphQLResult } from '#/lib/graphql/transport'

const mocks = vi.hoisted(() => ({
  beginAuthorization: vi.fn(),
  preflightOperation: vi.fn(),
}))

vi.mock('#/lib/auth/oidc', async (importOriginal) => {
  const actual = await importOriginal<typeof import('#/lib/auth/oidc')>()
  return {
    ...actual,
    beginAuthorization: mocks.beginAuthorization,
  }
})

vi.mock('@identity/graphql-access', () => ({
  preflightOperation: mocks.preflightOperation,
}))

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

function session(): AuthSession {
  const now = Math.floor(Date.now() / 1000)
  return {
    accessToken: 'access-token',
    idToken: 'id-token',
    expiresAt: Date.now() + 60_000,
    scope: config.scope,
    grantedScopes: ['openid', 'profile', 'email'],
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

function renderProbe(scopes: string[] = []) {
  return render(
    <RuntimeConfigProvider config={config}>
      <LocaleProvider>
        <AuthProvider>
          <RequestableAccessContext.Provider
            value={
              scopes.length ? { session: getAuthSession()!, scopes } : null
            }
          >
            <Probe />
          </RequestableAccessContext.Provider>
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
  mocks.preflightOperation
    .mockReset()
    .mockReturnValue({ status: 'allowed', requiredScopes: [] })
  requestApi = undefined
  authApi = undefined
})

describe('useGraphQL automatic reauthentication', () => {
  it('starts one redirect for concurrent step-up challenges without replaying a POST', async () => {
    setAuthSession(session())
    const fetchMock = vi
      .fn<typeof fetch>()
      .mockImplementation(() => Promise.resolve(challengeResponse()))
    vi.stubGlobal('fetch', fetchMock)
    renderProbe()

    let results: GraphQLResult<unknown>[] = []
    await act(async () => {
      const first = requestApi?.(
        'query Q { effectivePermissions { requestableScopes } }',
        {},
      )
      const second = requestApi?.(
        'query Q { effectivePermissions { requestableScopes } }',
        {},
      )
      results = await Promise.all([first!, second!])
    })

    expect(results).toHaveLength(2)
    expect(results.every((result) => Boolean(result.stepUp))).toBe(true)
    // Two GraphQL POSTs, one each. The stale responses are never replayed.
    expect(fetchMock).toHaveBeenCalledTimes(2)
    expect(mocks.beginAuthorization).toHaveBeenCalledTimes(1)
    expect(mocks.beginAuthorization.mock.calls[0][0].stepUp).toEqual({
      acrValues: 'aal2',
      maxAge: 0,
    })
  })

  it('treats a real 403 permission denial as a denial, not an authentication redirect', async () => {
    setAuthSession(session())
    const fetchMock = vi.fn<typeof fetch>().mockResolvedValue(
      new Response(
        JSON.stringify({
          data: null,
          errors: [
            {
              message: 'forbidden',
              extensions: {
                kind: 'authorization_error',
                code: 'permission_denied',
              },
            },
          ],
        }),
        { status: 403, headers: { 'Content-Type': 'application/json' } },
      ),
    )
    vi.stubGlobal('fetch', fetchMock)
    renderProbe()

    let result: GraphQLResult<unknown> | undefined
    await act(async () => {
      result = await requestApi?.(
        'query Q { effectivePermissions { requestableScopes } }',
        {},
      )
    })

    expect(result?.forbidden).toBe(true)
    expect(result?.unauthorized).toBe(false)
    expect(result?.stepUp).toBeUndefined()
    expect(fetchMock).toHaveBeenCalledTimes(1)
    expect(mocks.beginAuthorization).not.toHaveBeenCalled()
    expect(authApi?.status).toBe('authenticated')
  })

  it('redirects a rejected session to ordinary sign-in without opening a popup', async () => {
    const open = vi.spyOn(window, 'open')
    setAuthSession(session())
    const fetchMock = vi.fn<typeof fetch>().mockResolvedValue(
      new Response(
        JSON.stringify({
          data: null,
          errors: [
            { message: 'expired', extensions: { code: 'unauthenticated' } },
          ],
        }),
        { status: 401, headers: { 'Content-Type': 'application/json' } },
      ),
    )
    vi.stubGlobal('fetch', fetchMock)
    renderProbe()

    let result: GraphQLResult<unknown> | undefined
    await act(async () => {
      result = await requestApi?.(
        'query Q { effectivePermissions { requestableScopes } }',
        {},
      )
    })

    expect(result?.unauthorized).toBe(true)
    expect(fetchMock).toHaveBeenCalledTimes(1)
    expect(mocks.beginAuthorization).toHaveBeenCalledTimes(1)
    const options = mocks.beginAuthorization.mock.calls[0][0]
    expect(options.stepUp).toBeUndefined()
    expect(options.deferNavigation).toBeUndefined()
    expect(options.loginHint).toBeUndefined()
    expect(open).not.toHaveBeenCalled()
  })

  it('uses live eligibility to preflight a clipped write without replaying it', async () => {
    setAuthSession(session())
    mocks.preflightOperation
      .mockReturnValueOnce({
        status: 'forbidden',
        requiredScopes: ['management.group.write'],
      })
      .mockReturnValue({
        status: 'reauthentication',
        requiredScopes: ['management.group.write'],
        acrValues: 'aal2',
        maxAge: 300,
      })
    const fetchMock = vi.fn<typeof fetch>().mockResolvedValue(
      new Response(
        JSON.stringify({
          data: {
            effectivePermissions: { __typename: 'EffectivePermissions' },
          },
        }),
        { headers: { 'Content-Type': 'application/json' } },
      ),
    )
    vi.stubGlobal('fetch', fetchMock)
    renderProbe(['management.group.write'])
    let result: GraphQLResult<unknown> | undefined
    await act(async () => {
      result = await requestApi?.(
        'mutation Write($input: CreateGroupInput!) { createGroup(input: $input) { groupId } }',
        { input: { name: 'draft' } },
      )
    })
    expect(result?.stepUp?.requiredScopes).toEqual(['management.group.write'])
    expect(fetchMock).toHaveBeenCalledTimes(1)
    expect(
      JSON.parse(String(fetchMock.mock.calls[0][1]?.body)).query,
    ).toContain('ConsoleAuthenticationCheck')
    expect(mocks.beginAuthorization).toHaveBeenCalledTimes(1)
  })

  it('blocks a write locally without fetching or starting reauthentication', async () => {
    setAuthSession(session())
    mocks.preflightOperation.mockReturnValue({
      status: 'forbidden',
      requiredScopes: ['management.user.write'],
    })
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
    expect(result?.data).toBeNull()
    expect(result?.forbidden).toBe(true)
    expect(result?.unauthorized).toBe(false)
    expect(result?.stepUp).toBeUndefined()
    expect(result?.failure?.code).toBe('insufficient_scope')
    expect(result?.errors[0]?.code).toBe('insufficient_scope')
    expect(result?.errors[0]?.message).toBeTruthy()
    // Local decisions have no server request or trace to report.
    expect(result?.requestId).toBeUndefined()
    expect(result?.traceId).toBeUndefined()
  })

  it('routes a local fresh-auth requirement through the central flow once', async () => {
    setAuthSession(session())
    mocks.preflightOperation.mockReturnValue({
      status: 'reauthentication',
      requiredScopes: [],
      acrValues: 'aal2',
      maxAge: 300,
    })
    const fetchMock = vi
      .fn<typeof fetch>()
      .mockResolvedValue(
        new Response(
          JSON.stringify({
            data: {
              effectivePermissions: { __typename: 'EffectivePermissions' },
            },
          }),
          { status: 200, headers: { 'Content-Type': 'application/json' } },
        ),
      )
    vi.stubGlobal('fetch', fetchMock)
    renderProbe()

    let result: GraphQLResult<unknown> | undefined
    await act(async () => {
      result = await requestApi?.(
        'query Q { effectivePermissions { requestableScopes } }',
        {},
      )
    })

    expect(fetchMock).toHaveBeenCalledOnce()
    expect(
      JSON.parse(fetchMock.mock.calls[0][1]!.body as string).query,
    ).toContain('query ConsoleAuthenticationCheck')
    expect(mocks.beginAuthorization).toHaveBeenCalledTimes(1)
    expect(mocks.beginAuthorization.mock.calls[0][0].stepUp).toEqual({
      acrValues: 'aal2',
      maxAge: 0,
    })
    expect(result?.stepUp).toEqual({
      source: 'preflight',
      recoveryManaged: true,
      acrValues: 'aal2',
      maxAge: 300,
    })
    expect(result?.failure?.code).toBe('insufficient_user_authentication')
    expect(result?.errors[0]?.code).toBe('insufficient_user_authentication')
    expect(result?.forbidden).toBe(false)
    expect(result?.unauthorized).toBe(false)
    expect(result?.requestId).toBeUndefined()
    expect(result?.traceId).toBeUndefined()
  })

  it('lets an unknown preflight decision reach the backend and keeps the reactive challenge', async () => {
    setAuthSession(session())
    mocks.preflightOperation.mockReturnValue({
      status: 'unknown',
      requiredScopes: [],
    })
    const fetchMock = vi
      .fn<typeof fetch>()
      .mockResolvedValue(challengeResponse())
    vi.stubGlobal('fetch', fetchMock)
    renderProbe()

    let result: GraphQLResult<unknown> | undefined
    await act(async () => {
      result = await requestApi?.(
        'query Q { effectivePermissions { requestableScopes } }',
        {},
      )
    })

    expect(fetchMock).toHaveBeenCalledTimes(1)
    expect(result?.stepUp).toBeDefined()
    expect(mocks.beginAuthorization).toHaveBeenCalledTimes(1)
  })

  it('does not reopen recovery for a late response from a replaced session', async () => {
    setAuthSession(session())
    let respond!: (value: Response) => void
    vi.stubGlobal(
      'fetch',
      vi.fn(
        () =>
          new Promise<Response>((resolve) => {
            respond = resolve
          }),
      ),
    )
    renderProbe()
    const pending = requestApi!('query Q { effectivePermissions { requestableScopes } }', {})
    const refreshed = session()
    refreshed.accessToken = 'refreshed-access-token'
    setAuthSession(refreshed)
    let result: GraphQLResult<unknown> | undefined
    await act(async () => {
      respond(challengeResponse())
      result = await pending
    })
    expect(result?.stepUp?.recoveryManaged).toBe(true)
    expect(mocks.beginAuthorization).not.toHaveBeenCalled()
  })

  it('keeps an allowed no-scope bootstrap query on the network', async () => {
    setAuthSession(session())
    const fetchMock = vi.fn<typeof fetch>().mockResolvedValue(
      new Response(
        JSON.stringify({
          data: { effectivePermissions: { requestableScopes: [] } },
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
        'query Q { effectivePermissions { requestableScopes } }',
        {},
      )
    })

    expect(fetchMock).toHaveBeenCalledTimes(1)
    expect(result?.data).not.toBeNull()
    expect(result?.failure).toBeUndefined()
    expect(mocks.preflightOperation).toHaveBeenCalledWith(
      'query Q { effectivePermissions { requestableScopes } }',
      {},
      expect.objectContaining({
        scopes: ['openid', 'profile', 'email'],
        user: true,
      }),
      undefined,
    )
    expect(mocks.beginAuthorization).not.toHaveBeenCalled()
  })
})
