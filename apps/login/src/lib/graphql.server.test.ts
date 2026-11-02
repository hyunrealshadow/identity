import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

import { AccountSessionExpiredError, GraphqlRequestError, identityGraphql, parseStepUpChallenge, preflightIdentityGraphql, accountAccessContext } from './graphql.server'

const mocks = vi.hoisted(() => ({
  accessToken: vi.fn(),
  clearAuthorizationCookie: vi.fn(),
  elevatedAccessToken: vi.fn(),
  forwardRequestContext: vi.fn((headers: Headers) => headers),
}))

vi.mock('./oauth.server', () => ({
  accessToken: mocks.accessToken,
  clearAuthorizationCookie: mocks.clearAuthorizationCookie,
  elevatedAccessToken: mocks.elevatedAccessToken,
}))

vi.mock('./request-context.server', () => ({
  forwardRequestContext: mocks.forwardRequestContext,
}))

vi.mock('./i18n.server', () => ({ requestLocale: () => 'zh-CN' }))

beforeEach(() => {
  delete process.env.IDENTITY_BACKCHANNEL_API_URL
  delete process.env.IDENTITY_BACKCHANNEL_GRAPHQL_URL
  delete process.env.IDENTITY_BACKCHANNEL_ALLOW_HTTP
  mocks.accessToken.mockResolvedValue('access-token')
  mocks.elevatedAccessToken.mockResolvedValue(undefined)
  mocks.clearAuthorizationCookie.mockResolvedValue(undefined)
})

afterEach(() => {
  delete process.env.IDENTITY_BACKCHANNEL_API_URL
  delete process.env.IDENTITY_BACKCHANNEL_GRAPHQL_URL
  delete process.env.IDENTITY_BACKCHANNEL_ALLOW_HTTP
  vi.unstubAllGlobals()
  vi.clearAllMocks()
})

describe('parseStepUpChallenge', () => {
  it('reads RFC 9470 authentication requirements', () => {
    expect(
      parseStepUpChallenge(
        'Bearer realm="graphql", error="insufficient_user_authentication", acr_values="aal2", max_age="3600"',
      ),
    ).toEqual({
      acrValues: 'aal2',
      maxAge: 3600,
    })
  })

  it('ignores ordinary invalid-token challenges', () => {
    expect(
      parseStepUpChallenge('Bearer error="invalid_token"'),
    ).toBeUndefined()
  })
})

describe('identityGraphql', () => {
  function token(scopes: string, acr = 'aal2', age = 0) {
    return `header.${Buffer.from(JSON.stringify({
      sub: 'user', scope: scopes, acr,
      auth_time: Math.floor(Date.now() / 1000) - age,
    })).toString('base64url')}.signature`
  }

  it('exports only safe claims for the browser using the same token selection', async () => {
    const standard = token('account.read account.update', 'aal1', 400)
    const elevated = token('account.read account.update password.change', 'aal2', 20)
    mocks.accessToken.mockResolvedValue(standard)
    mocks.elevatedAccessToken.mockResolvedValue(elevated)
    const context = await accountAccessContext(true)
    expect(context.default).toMatchObject({ scopes: ['account.read', 'account.update'], acr: 'aal1', user: true, mfaEnabled: true })
    expect(context.elevated).toMatchObject({ scopes: ['account.read', 'account.update', 'password.change'], acr: 'aal2' })
    expect(JSON.stringify(context)).not.toContain(standard)
    expect(JSON.stringify(context)).not.toContain(elevated)
    expect(Object.keys(context.default!)).toEqual(['scopes', 'acr', 'authTime', 'user', 'mfaEnabled'])
  })

  it('blocks a missing directive scope locally with a translated denial', async () => {
    mocks.accessToken.mockResolvedValue(token('account.read'))
    const fetch = vi.fn()
    vi.stubGlobal('fetch', fetch)
    await expect(identityGraphql('mutation { updateProfile(input: {}) { user { id } } }')).rejects.toMatchObject({
      errors: [{ message: '没有执行此操作的权限', extensions: { code: 'insufficient_scope', requiredScopes: ['account.update'] } }],
    })
    expect(fetch).not.toHaveBeenCalled()
    expect(mocks.clearAuthorizationCookie).not.toHaveBeenCalled()
  })

  it('prechecks a form-opening operation without submitting the mutation', async () => {
    mocks.accessToken.mockResolvedValue(token('password.change', 'aal2', 100))
    const fetch = vi.fn()
    vi.stubGlobal('fetch', fetch)
    await preflightIdentityGraphql('mutation Change($input: ChangePasswordInput!) { changePassword(input: $input) { changed } }')
    expect(fetch).not.toHaveBeenCalled()
  })

  it('prechecks schema freshness before submitting an account write', async () => {
    mocks.accessToken.mockResolvedValue(token('account.update', 'aal1', 301))
    const fetch = vi.fn()
    vi.stubGlobal('fetch', fetch)
    await expect(identityGraphql('mutation { updateUsername(input: {username: "new-name"}) { user { id } } }')).rejects.toMatchObject({
      challenge: { maxAge: 300 },
      errors: [{ extensions: { code: 'insufficient_user_authentication' } }],
    })
    expect(fetch).not.toHaveBeenCalled()
  })

  it('resolves the schema account-factor condition without submitting the write', async () => {
    mocks.accessToken.mockResolvedValue(token('account.read account.update', 'aal1', 0))
    const fetch = vi.fn().mockResolvedValue(jsonResponse({ data: { security: { mfaEnabled: true } } }))
    vi.stubGlobal('fetch', fetch)
    await expect(identityGraphql('mutation { beginTotpEnrollment { clientMutationId } }')).rejects.toMatchObject({
      challenge: { acrValues: 'aal2', maxAge: 3600 },
    })
    expect(fetch).toHaveBeenCalledOnce()
    expect(JSON.parse((fetch.mock.calls[0]?.[1] as RequestInit).body as string).query).toContain('security { mfaEnabled }')
  })

  it('permits a fresh AAL2 security write without another factors query', async () => {
    mocks.accessToken.mockResolvedValue(token('account.read account.update', 'aal2', 100))
    const fetch = vi.fn().mockResolvedValue(jsonResponse({ data: { prepareMfaManagement: true } }))
    vi.stubGlobal('fetch', fetch)
    await expect(identityGraphql('mutation { prepareMfaManagement }')).resolves.toEqual({ prepareMfaManagement: true })
    expect(fetch).toHaveBeenCalledOnce()
  })

  it('prioritizes a missing permission over stale authentication', async () => {
    mocks.accessToken.mockResolvedValue(token('account.read', 'aal1', 1000))
    vi.stubGlobal('fetch', vi.fn())
    try {
      await identityGraphql('mutation { updateUsername(input: {username: "new-name"}) { user { id } } }')
      expect.fail('expected denial')
    } catch (error) {
      expect(error).toBeInstanceOf(GraphqlRequestError)
      expect((error as GraphqlRequestError).challenge).toBeUndefined()
    }
    expect(fetch).not.toHaveBeenCalled()
  })

  it('uses the dedicated internal GraphQL endpoint', async () => {
    process.env.IDENTITY_BACKCHANNEL_GRAPHQL_URL =
      'http://identity-server:5152'
    process.env.IDENTITY_BACKCHANNEL_ALLOW_HTTP = 'true'
    const fetch = vi
      .fn()
      .mockResolvedValue(jsonResponse({ data: { account: true } }))
    vi.stubGlobal('fetch', fetch)

    await identityGraphql('query Account { account { id } }')

    expect(fetch.mock.calls[0]?.[0]).toEqual(
      new URL('http://identity-server:5152/graphql'),
    )
  })

  it('prefers a valid elevated token for elevated account mutations', async () => {
    mocks.elevatedAccessToken.mockResolvedValue('elevated-token')
    const fetch = vi.fn().mockResolvedValue(jsonResponse({ data: { changed: true } }))
    vi.stubGlobal('fetch', fetch)

    await expect(identityGraphql<{ changed: boolean }>(
      'mutation ChangePassword { changePassword { changed } }',
      undefined,
      { authorization: 'elevated' },
    )).resolves.toEqual({ changed: true })

    const request = fetch.mock.calls[0]?.[1] as RequestInit
    expect(new Headers(request.headers).get('authorization')).toBe('Bearer elevated-token')
    expect(mocks.accessToken).not.toHaveBeenCalled()
  })

  it('falls back to the ordinary token when no elevated token is available', async () => {
    const fetch = vi.fn().mockResolvedValue(jsonResponse({ data: { changed: true } }))
    vi.stubGlobal('fetch', fetch)

    await identityGraphql('mutation Update { updateProfile { clientMutationId } }', undefined, {
      authorization: 'elevated',
    })

    expect(mocks.accessToken).toHaveBeenCalledOnce()
    const request = fetch.mock.calls[0]?.[1] as RequestInit
    expect(new Headers(request.headers).get('authorization')).toBe('Bearer access-token')
  })

  it('exposes RFC 9470 requirements without clearing the current login', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(jsonResponse(
      { errors: [{ message: 'recent authentication is required' }] },
      401,
      { 'www-authenticate': 'Bearer error="insufficient_user_authentication", acr_values="aal2", max_age="3600"' },
    )))

    const error = await identityGraphql('mutation Sensitive { disableTotp { changed } }')
      .catch((caught: unknown) => caught)

    expect(error).toBeInstanceOf(GraphqlRequestError)
    expect((error as GraphqlRequestError).challenge).toEqual({
      acrValues: 'aal2',
      maxAge: 3600,
    })
    expect(mocks.clearAuthorizationCookie).not.toHaveBeenCalled()
  })

  it('clears the authorization cookie for an ordinary unauthorized response', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(jsonResponse(
      { errors: [{ message: 'invalid token' }] },
      401,
      { 'www-authenticate': 'Bearer error="invalid_token"' },
    )))

    await expect(identityGraphql('query Account { account { id } }')).resolves.toBeUndefined()
    expect(mocks.clearAuthorizationCookie).toHaveBeenCalledOnce()
  })

  it('rejects successful HTTP responses that contain GraphQL errors', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(jsonResponse({
      errors: [{ message: 'validation failed', extensions: { kind: 'validation' } }],
    })))

    await expect(identityGraphql('mutation Invalid { updateProfile { clientMutationId } }'))
      .rejects.toMatchObject({ message: 'validation failed' })
  })
})

function jsonResponse(
  payload: unknown,
  status = 200,
  headers?: HeadersInit,
) {
  return new Response(JSON.stringify(payload), {
    status,
    headers: { 'content-type': 'application/json', ...headers },
  })
}

it('requires ordinary sign-in when a form preflight has no usable token', async () => {
  mocks.accessToken.mockResolvedValue(undefined)
  const fetch = vi.fn()
  vi.stubGlobal('fetch', fetch)
  await expect(preflightIdentityGraphql('mutation { prepareMfaManagement }')).rejects.toBeInstanceOf(AccountSessionExpiredError)
  expect(fetch).not.toHaveBeenCalled()
})
