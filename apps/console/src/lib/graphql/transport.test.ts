import { describe, expect, it, vi } from 'vitest'

import { executeGraphQL, fieldErrorMap } from './transport'

const TRACE = '0123456789abcdef0123456789abcdef'

describe('executeGraphQL', () => {
  it('keeps partial data and errors, maps fields, correlation and step-up', async () => {
    const fetchMock = vi.fn<typeof fetch>().mockResolvedValue(
      new Response(
        JSON.stringify({
          data: { updateProfile: { user: { id: 'user-1' } } },
          errors: [
            {
              message: 'server detail',
              path: ['updateProfile', 'user'],
              extensions: {
                kind: 'validation',
                code: 'insufficient_user_authentication',
                requestId: 'err-req',
                traceId: TRACE,
                fields: { givenName: 'invalid value' },
                acr_values: 'urn:extension',
                max_age: 120,
              },
            },
          ],
          extensions: { requestId: 'response-req', traceId: TRACE },
        }),
        {
          status: 200,
          headers: {
            'Content-Type': 'application/json',
            'X-Request-ID': 'header-req',
            'X-Trace-ID': TRACE,
            'WWW-Authenticate':
              'Bearer error="insufficient_user_authentication", acr_values="urn:header", max_age="60"',
          },
        },
      ),
    )

    const result = await executeGraphQL<{ updateProfile: { user: { id: string } } }, { input: { givenName: string } }>(
      'mutation UpdateProfile($input: UpdateProfileInput!) { updateProfile(input: $input) { user { id } } }',
      {
        graphqlUrl: 'https://identity.example/graphql',
        accessToken: 'access-token',
        locale: 'zh-CN',
        variables: { input: { givenName: 'x' } },
        operationName: 'UpdateProfile',
        activeTraceId: 'not-a-trace-id',
        fetchImpl: fetchMock,
      },
    )

    expect(fetchMock).toHaveBeenCalledTimes(1)
    const [, init] = fetchMock.mock.calls[0]
    const headers = init?.headers as Record<string, string>
    expect(headers.Authorization).toBe('Bearer access-token')
    expect(headers['Accept-Language']).toBe('zh-CN')
    expect(headers['X-Request-ID']).toBeUndefined()
    expect(headers['X-Trace-ID']).toBeUndefined()

    expect(result.data?.updateProfile.user.id).toBe('user-1')
    expect(result.partial).toBe(true)
    expect(result.requestId).toBe('response-req')
    expect(result.traceId).toBe(TRACE)
    expect(result.errors[0].fields).toEqual([
      { path: 'givenName', message: 'invalid value' },
    ])
    expect(fieldErrorMap(result.errors)).toEqual({ givenName: 'invalid value' })
    expect(result.stepUp).toMatchObject({
      acrValues: 'urn:extension',
      maxAge: 120,
      requestId: 'err-req',
      traceId: TRACE,
      source: 'both',
    })
  })

  it('extracts step-up from WWW-Authenticate when GraphQL extensions do not provide it', async () => {
    const fetchMock = vi.fn<typeof fetch>().mockResolvedValue(
      new Response(
        JSON.stringify({
          data: null,
          errors: [{ message: 'challenge', extensions: { kind: 'graphql' } }],
        }),
        {
          status: 401,
          headers: {
            'Content-Type': 'application/json',
            'WWW-Authenticate':
              'Bearer error="insufficient_user_authentication", acr_values="urn:aal2", max_age="30"',
          },
        },
      ),
    )

    const result = await executeGraphQL('query SelfSecurity { security { mfaEnabled } }', {
      graphqlUrl: 'https://identity.example/graphql',
      accessToken: 'token',
      locale: 'en-US',
      variables: {},
      fetchImpl: fetchMock,
    })

    expect(result.stepUp).toMatchObject({
      acrValues: 'urn:aal2',
      maxAge: 30,
      source: 'www-authenticate',
    })
    expect(result.unauthorized).toBe(false)
    expect(result.failure?.kind).toBe('graphql')
    expect(fetchMock).toHaveBeenCalledTimes(1)
  })

  it('returns a typed unauthorized failure for HTTP 401 without replay', async () => {
    const fetchMock = vi.fn<typeof fetch>().mockResolvedValue(
      new Response(
        JSON.stringify({
          errors: [{ message: 'expired', extensions: { code: 'unauthenticated' } }],
        }),
        {
          status: 401,
          headers: { 'Content-Type': 'application/json', 'X-Request-ID': 'req-401' },
        },
      ),
    )

    const result = await executeGraphQL('mutation RevokeSession { revokeSession(id: "1") { clientMutationId } }', {
      graphqlUrl: 'https://identity.example/graphql',
      accessToken: 'expired',
      locale: 'en-US',
      variables: {},
      fetchImpl: fetchMock,
    })

    expect(result.unauthorized).toBe(true)
    expect(result.failure).toMatchObject({ kind: 'unauthorized', status: 401 })
    expect(result.requestId).toBe('req-401')
    expect(fetchMock).toHaveBeenCalledTimes(1)
  })

  it('never retries a sensitive mutation after a GraphQL error', async () => {
    const fetchMock = vi.fn<typeof fetch>().mockResolvedValue(
      new Response(
        JSON.stringify({
          data: null,
          errors: [{ message: 'failed', extensions: { kind: 'conflict', code: 'conflict' } }],
        }),
        { status: 200, headers: { 'Content-Type': 'application/json' } },
      ),
    )

    const result = await executeGraphQL('mutation UpdateProfile($input: UpdateProfileInput!) { updateProfile(input: $input) { clientMutationId } }', {
      graphqlUrl: 'https://identity.example/graphql',
      accessToken: 'token',
      locale: 'en-US',
      variables: { input: { nickname: 'x' } },
      fetchImpl: fetchMock,
    })

    expect(result.failure).toMatchObject({ kind: 'graphql', code: 'conflict' })
    expect(fetchMock).toHaveBeenCalledTimes(1)
  })
})
