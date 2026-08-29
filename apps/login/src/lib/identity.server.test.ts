import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

import {
  IdentityApiError,
  identityInternalJson,
  identityJson,
  isTerminalLoginError,
} from './identity.server'

const mocks = vi.hoisted(() => ({
  forwardRequestContext: vi.fn((headers: Headers) => {
    headers.set('user-agent', 'Forwarded Browser')
    headers.set('x-forwarded-for', '203.0.113.10')
    return headers
  }),
  getRequestHeader: vi.fn(),
  setResponseHeader: vi.fn(),
}))

vi.mock('@tanstack/react-start/server', () => ({
  getRequestHeader: mocks.getRequestHeader,
  setResponseHeader: mocks.setResponseHeader,
}))

vi.mock('./request-context.server', () => ({
  forwardRequestContext: mocks.forwardRequestContext,
}))

beforeEach(() => {
  vi.clearAllMocks()
  mocks.getRequestHeader.mockReturnValue(undefined)
  delete process.env.IDENTITY_API_URL
  delete process.env.IDENTITY_INTERNAL_API_URL
  delete process.env.IDENTITY_INTERNAL_API_ALLOW_HTTP
  delete process.env.IDENTITY_WORKLOAD_TOKEN
})

afterEach(() => {
  vi.unstubAllGlobals()
  delete process.env.IDENTITY_API_URL
  delete process.env.IDENTITY_INTERNAL_API_URL
  delete process.env.IDENTITY_INTERNAL_API_ALLOW_HTTP
  delete process.env.IDENTITY_WORKLOAD_TOKEN
})

describe('identityJson', () => {
  it('forwards request context and valid session IDs without replacing the user agent', async () => {
    mocks.getRequestHeader.mockImplementation((name: string) =>
      name === 'cookie'
        ? `identity.sessions=${encodeURIComponent(JSON.stringify(['session-a', 'session-b']))}`
        : undefined,
    )
    const fetch = vi.fn().mockResolvedValue(jsonResponse({ ok: true }))
    vi.stubGlobal('fetch', fetch)

    await identityJson('/api/auth/sessions/active')

    const [, init] = fetch.mock.calls[0] as [URL, RequestInit]
    const headers = new Headers(init.headers)
    expect(headers.get('user-agent')).toBe('Forwarded Browser')
    expect(headers.get('x-forwarded-for')).toBe('203.0.113.10')
    expect(headers.get('x-sessions')).toBe('["session-a","session-b"]')
  })

  it('ignores malformed or non-string session cookie entries', async () => {
    mocks.getRequestHeader.mockReturnValue(
      `identity.sessions=${encodeURIComponent(JSON.stringify(['valid', 42]))}`,
    )
    const fetch = vi.fn().mockResolvedValue(jsonResponse({ ok: true }))
    vi.stubGlobal('fetch', fetch)

    await identityJson('/api/auth/sessions/active')

    const [, init] = fetch.mock.calls[0] as [URL, RequestInit]
    expect(new Headers(init.headers).get('x-sessions')).toBe('[]')
  })

  it('stores session IDs returned by the Identity API in a hardened cookie', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(jsonResponse({
      sessions: ['new-session'],
    })))

    await identityJson('/api/auth/login/identifier')

    expect(mocks.setResponseHeader).toHaveBeenCalledWith(
      'set-cookie',
      expect.stringMatching(/^identity\.sessions=.*Path=\/; HttpOnly; Secure; SameSite=Lax; Max-Age=/),
    )
  })

  it('does not rewrite an unchanged session cookie', async () => {
    const sessions = ['session-a', 'session-b']
    mocks.getRequestHeader.mockImplementation((name: string) =>
      name === 'cookie'
        ? `identity.sessions=${encodeURIComponent(JSON.stringify(sessions))}`
        : undefined,
    )
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(jsonResponse({ sessions })))

    await identityJson('/api/auth/sessions/active')

    expect(mocks.setResponseHeader).not.toHaveBeenCalled()
  })

  it('does not create an empty session cookie when no sessions are active', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(jsonResponse({ sessions: [] })))

    await identityJson('/api/auth/sessions/active')

    expect(mocks.setResponseHeader).not.toHaveBeenCalled()
  })

  it('preserves structured business and field errors', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(jsonResponse({
      error: {
        code: 15004,
        message: 'Email address is invalid',
        fields: [{ field: 'email', code: 15004, message: 'Enter a valid email' }],
      },
    }, 422)))

    const error = await identityJson('/install').catch((caught: unknown) => caught)

    expect(error).toBeInstanceOf(IdentityApiError)
    expect(error).toMatchObject({
      status: 422,
      code: 15004,
      fields: [{ field: 'email', code: 15004, message: 'Enter a valid email' }],
    })
  })

  it('refuses a plaintext Identity API endpoint', async () => {
    process.env.IDENTITY_API_URL = 'http://identity.example.com'

    await expect(identityJson('/installation/status')).rejects.toThrow(
      'IDENTITY_API_URL must use HTTPS',
    )
  })
})

describe('isTerminalLoginError', () => {
  it.each([11004, 11005])('restarts terminal login error %i', (code) => {
    expect(isTerminalLoginError(new IdentityApiError('restart', 410, code))).toBe(true)
  })

  it('keeps retryable credential errors on the challenge page', () => {
    expect(isTerminalLoginError(new IdentityApiError('retry', 401, 11007))).toBe(false)
  })
})

describe('identityInternalJson', () => {
  it('rejects plaintext internal traffic unless it is explicitly enabled', async () => {
    process.env.IDENTITY_INTERNAL_API_URL = 'http://identity:5151'
    process.env.IDENTITY_WORKLOAD_TOKEN = 'a'.repeat(32)

    await expect(
      identityInternalJson('/internal/workloads/self/runtime-configuration'),
    ).rejects.toThrow('IDENTITY_INTERNAL_API_URL must use HTTPS')
  })

  it('allows explicitly configured plaintext internal traffic', async () => {
    process.env.IDENTITY_INTERNAL_API_URL = 'http://identity:5151'
    process.env.IDENTITY_INTERNAL_API_ALLOW_HTTP = 'true'
    process.env.IDENTITY_WORKLOAD_TOKEN = 'a'.repeat(32)
    const fetch = vi.fn().mockResolvedValue(jsonResponse({ ok: true }))
    vi.stubGlobal('fetch', fetch)

    await identityInternalJson('/internal/workloads/self/runtime-configuration')

    expect(fetch.mock.calls[0]?.[0]).toEqual(
      new URL('http://identity:5151/internal/workloads/self/runtime-configuration'),
    )
  })
})

function jsonResponse(payload: unknown, status = 200) {
  return new Response(JSON.stringify(payload), {
    status,
    headers: { 'content-type': 'application/json' },
  })
}
