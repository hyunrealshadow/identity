import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

import { GraphqlRequestError, identityGraphql, parseStepUpChallenge } from './graphql.server'

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
        'Bearer realm="graphql", error="insufficient_user_authentication", acr_values="urn:identity:acr:aal2", max_age="3600"',
      ),
    ).toEqual({
      acrValues: 'urn:identity:acr:aal2',
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
  it('uses the dedicated internal GraphQL endpoint', async () => {
    process.env.IDENTITY_BACKCHANNEL_GRAPHQL_URL =
      'http://identity-server:5152'
    process.env.IDENTITY_BACKCHANNEL_ALLOW_HTTP = 'true'
    const fetch = vi
      .fn()
      .mockResolvedValue(jsonResponse({ data: { viewer: true } }))
    vi.stubGlobal('fetch', fetch)

    await identityGraphql('query Viewer { viewer }')

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
      { 'www-authenticate': 'Bearer error="insufficient_user_authentication", acr_values="urn:identity:acr:aal2", max_age="3600"' },
    )))

    const error = await identityGraphql('mutation Sensitive { disableTotp { changed } }')
      .catch((caught: unknown) => caught)

    expect(error).toBeInstanceOf(GraphqlRequestError)
    expect((error as GraphqlRequestError).challenge).toEqual({
      acrValues: 'urn:identity:acr:aal2',
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

    await expect(identityGraphql('query Viewer { viewer { account { id } } }')).resolves.toBeUndefined()
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
