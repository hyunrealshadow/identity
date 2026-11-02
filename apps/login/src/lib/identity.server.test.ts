import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

import {
  errorMessage,
  IdentityApiError,
  identityInternalJson,
  identityJson,
  isTerminalLoginError,
  LocalizedError,
  UpstreamTransportError,
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
  delete process.env.IDENTITY_BACKCHANNEL_API_URL
  delete process.env.IDENTITY_BACKCHANNEL_ALLOW_HTTP
  delete process.env.IDENTITY_INTERNAL_API_URL
  delete process.env.IDENTITY_INTERNAL_API_ALLOW_HTTP
  delete process.env.IDENTITY_WORKLOAD_TOKEN
})

afterEach(() => {
  vi.unstubAllGlobals()
  delete process.env.IDENTITY_API_URL
  delete process.env.IDENTITY_BACKCHANNEL_API_URL
  delete process.env.IDENTITY_BACKCHANNEL_ALLOW_HTTP
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

  it('renews the cookie lifetime after authentication reuses the existing session', async () => {
    const sessions = ['existing-session']
    const cookie = `identity.sessions=${encodeURIComponent(JSON.stringify(sessions))}`
    mocks.getRequestHeader.mockReturnValue(cookie)
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(jsonResponse({
      status: 'authenticated', sessions,
    })))

    await identityJson('/api/auth/login/challenge', { method: 'POST' })

    expect(mocks.setResponseHeader).toHaveBeenCalledWith(
      'set-cookie', `${cookie}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=604800`,
    )
  })

  it('does not renew the cookie while MFA is still required', async () => {
    const sessions = ['existing-session']
    mocks.getRequestHeader.mockReturnValue(
      `identity.sessions=${encodeURIComponent(JSON.stringify(sessions))}`,
    )
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(jsonResponse({
      status: 'mfa_required', sessions,
    })))

    await identityJson('/api/auth/login/challenge', { method: 'POST' })

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

  it('keeps transport failures on the cause chain for server diagnostics', async () => {
    const failure = new TypeError('fetch failed')
    vi.stubGlobal('fetch', vi.fn().mockRejectedValue(failure))

    const error = await identityJson('/api/auth/login/unknown').catch(
      (caught: unknown) => caught,
    )

    expect(error).toBeInstanceOf(UpstreamTransportError)
    expect((error as UpstreamTransportError).cause).toBe(failure)
    expect(errorMessage(error, 'zh-CN')).toBe('请求暂时无法完成，请稍后重试')
  })

  it('refuses a plaintext Identity API endpoint', async () => {
    process.env.IDENTITY_BACKCHANNEL_API_URL = 'http://identity.example.com'

    await expect(identityJson('/installation/status')).rejects.toThrow(
      'IDENTITY_BACKCHANNEL_API_URL must use HTTPS',
    )
  })

  it('uses an explicitly enabled HTTP backchannel instead of the public URL', async () => {
    process.env.IDENTITY_API_URL = 'https://identity.example.com'
    process.env.IDENTITY_BACKCHANNEL_API_URL = 'http://identity-server:5150'
    process.env.IDENTITY_BACKCHANNEL_ALLOW_HTTP = 'true'
    const fetch = vi.fn().mockResolvedValue(jsonResponse({ ok: true }))
    vi.stubGlobal('fetch', fetch)

    await identityJson('/api/auth/sessions/active')

    expect(fetch.mock.calls[0]?.[0]).toEqual(
      new URL('http://identity-server:5150/api/auth/sessions/active'),
    )
  })

  it('rejects an HTTP backchannel unless it is explicitly enabled', async () => {
    process.env.IDENTITY_BACKCHANNEL_API_URL = 'http://identity-server:5150'

    await expect(identityJson('/api/auth/sessions/active')).rejects.toThrow(
      'IDENTITY_BACKCHANNEL_API_URL must use HTTPS',
    )
  })
})

describe('errorMessage', () => {
  it.each([
    ['en-US', 'The request cannot be completed right now. Try again later.'],
    ['zh-CN', '请求暂时无法完成，请稍后重试'],
  ] as const)(
    'uses the localized temporary message for unknown failures in %s',
    (locale, expected) => {
      expect(errorMessage(new Error('fetch failed'), locale)).toBe(expected)
      expect(errorMessage(new TypeError('getaddrinfo ENOTFOUND api'), locale)).toBe(expected)
      expect(errorMessage('upstream unavailable', locale)).toBe(expected)
    },
  )

  it('never exposes technical transport or internal text', () => {
    const message = errorMessage(
      new Error('connect ECONNREFUSED 10.0.0.1:443 certificate verify failed'),
      'en-US',
    )

    expect(message).not.toContain('ECONNREFUSED')
    expect(message).not.toContain('certificate')
    expect(message).not.toContain('fetch failed')
  })

  it('maps status-only API failures to the temporary message', () => {
    expect(
      errorMessage(new IdentityApiError('Identity API request failed (503)', 503), 'zh-CN'),
    ).toBe('请求暂时无法完成，请稍后重试')
  })

  it('keeps explicit localized presentation messages', () => {
    expect(errorMessage(new LocalizedError('Enter a valid email'), 'zh-CN'))
      .toBe('Enter a valid email')
  })

  it('keeps typed business messages and their field errors', () => {
    const error = new IdentityApiError('Email address is invalid', 422, 15004, [
      { field: 'email', code: 15004, message: 'Enter a valid email' },
    ])

    expect(errorMessage(error, 'zh-CN')).toBe('Email address is invalid')
    expect(error.fields).toEqual([
      { field: 'email', code: 15004, message: 'Enter a valid email' },
    ])
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
  it('forwards browser language for localized internal business errors', async () => {
    process.env.IDENTITY_WORKLOAD_TOKEN = 'a'.repeat(32)
    const fetch = vi.fn().mockResolvedValue(jsonResponse({
      error: {
        code: 13006,
        message: '邮箱地址格式无效',
        fields: [{ field: 'email', code: 13006, message: '邮箱地址格式无效' }],
      },
    }, 422))
    vi.stubGlobal('fetch', fetch)
    const error = await identityInternalJson('/internal/installation', {
      method: 'POST', body: { email: 'invalid' }, locale: 'zh-CN',
    }).catch((error: unknown) => error)
    const headers = new Headers(fetch.mock.calls[0][1].headers)
    expect(headers.get('accept-language')).toBe('zh-CN')
    expect(headers.get('authorization')).toBe(`Bearer ${'a'.repeat(32)}`)
    expect((error as IdentityApiError).fields[0].message).toBe('邮箱地址格式无效')
  })

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
