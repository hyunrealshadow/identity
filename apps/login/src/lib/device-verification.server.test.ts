import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

import {
  beginDeviceVerification,
  decideDeviceVerification,
  deviceInteractionPath,
  loadDeviceVerification,
} from './device-verification.server'

const mocks = vi.hoisted(() => ({
  getRequestHeader: vi.fn(),
  setResponseHeader: vi.fn(),
}))

vi.mock('@tanstack/react-start/server', () => ({
  getRequestHeader: mocks.getRequestHeader,
  setResponseHeader: mocks.setResponseHeader,
}))

vi.mock('./request-context.server', () => ({
  forwardRequestContext: (headers: Headers) => headers,
}))

beforeEach(() => {
  vi.clearAllMocks()
  process.env.IDENTITY_BACKCHANNEL_API_URL = 'https://identity.example.com'
})

afterEach(() => {
  vi.unstubAllGlobals()
  delete process.env.IDENTITY_BACKCHANNEL_API_URL
})

describe('beginDeviceVerification', () => {
  it('checks the code before a CSRF-protected native begin, without approving', async () => {
    const fetch = vi.fn<typeof globalThis.fetch>()
      .mockResolvedValueOnce(jsonResponse({ csrf_token: 'bootstrap-csrf' }))
      .mockResolvedValueOnce(jsonResponse({
        login_id: 'native-login', login_uri: '/login?login_id=native-login',
      }))
    vi.stubGlobal('fetch', fetch)

    await expect(beginDeviceVerification('WDJB MJHT', 'en-US')).resolves.toEqual({
      status: 'login', loginUri: '/login?login_id=native-login',
    })
    expect(fetch).toHaveBeenCalledTimes(2)
    expect(String(fetch.mock.calls[0][0])).toBe(
      'https://identity.example.com/oauth2/consent?user_code=WDJB%20MJHT',
    )
    expect(fetch.mock.calls[0][1]?.method).toBe('GET')
    expect(fetch.mock.calls[0][1]?.body).toBeUndefined()
    expect(String(fetch.mock.calls[1][0])).toBe(
      'https://identity.example.com/oauth2/device/login',
    )
    const begin = fetch.mock.calls[1][1]
    expect(begin?.method).toBe('POST')
    expect(new Headers(begin?.headers).get('x-csrf-token')).toBe('bootstrap-csrf')
    expect(JSON.parse(String(begin?.body))).toEqual({ user_code: 'WDJB MJHT' })
  })

  it('reports an unknown code before starting any login', async () => {
    const fetch = vi.fn().mockResolvedValue(businessError(422, 26010))
    vi.stubGlobal('fetch', fetch)

    await expect(beginDeviceVerification('ZZZZ-ZZZZ', 'en-US')).resolves.toEqual({
      status: 'unknown',
    })
    expect(fetch).toHaveBeenCalledTimes(1)
  })

  it('keeps a code invalidated between check and begin on the entry form', async () => {
    vi.stubGlobal('fetch', vi.fn()
      .mockResolvedValueOnce(jsonResponse({ csrf_token: 'csrf' }))
      .mockResolvedValueOnce(businessError(422, 26010)))
    await expect(beginDeviceVerification('WDJB-MJHT', 'en-US')).resolves.toEqual({
      status: 'unknown',
    })
  })

  it('preserves locale and sends all existing sessions to the native account picker', async () => {
    mocks.getRequestHeader.mockReturnValue(
      `identity.sessions=${encodeURIComponent(JSON.stringify(['session-a', 'session-b']))}`,
    )
    const fetch = vi.fn<typeof globalThis.fetch>()
      .mockResolvedValueOnce(jsonResponse({ csrf_token: 'csrf' }))
      .mockResolvedValueOnce(jsonResponse({
        login_id: 'login', login_uri: '/login?login_id=login',
      }))
    vi.stubGlobal('fetch', fetch)

    await expect(beginDeviceVerification('WDJB-MJHT', 'zh-CN', 'zh-CN en-US'))
      .resolves.toEqual({
        status: 'login', loginUri: '/login?login_id=login&ui_locales=zh-CN+en-US',
      })
    for (const [, init] of fetch.mock.calls) {
      expect(new Headers(init?.headers).get('x-sessions'))
        .toBe('["session-a","session-b"]')
    }
    expect(mocks.setResponseHeader).not.toHaveBeenCalled()
  })

  it('does not turn service failures into code errors or start login', async () => {
    const fetch = vi.fn().mockResolvedValue(businessError(500, 26012))
    vi.stubGlobal('fetch', fetch)
    expect((await beginDeviceVerification('WDJB-MJHT', 'en-US')).status).toBe('failed')
    expect(fetch).toHaveBeenCalledTimes(1)
  })

  it('reports transport failures without pretending the code is wrong', async () => {
    vi.stubGlobal('fetch', vi.fn().mockRejectedValue(new Error('fetch failed')))
    await expect(beginDeviceVerification('WDJB-MJHT', 'en-US')).resolves.toEqual({
      status: 'failed', message: 'fetch failed',
    })
  })
})

describe('bound device interaction', () => {
  it('reloads confirmation by login_id only and preserves the bound account', async () => {
    const description = {
      login_id: 'bound/login', user_code: 'WDJB-MJHT',
      account: { name: 'Selected account', email: 'selected@example.com' },
    }
    const fetch = vi.fn<typeof globalThis.fetch>().mockResolvedValue(jsonResponse(description))
    vi.stubGlobal('fetch', fetch)

    await expect(loadDeviceVerification('bound/login', 'en-US')).resolves.toEqual({
      status: 'described', description,
    })
    expect(String(fetch.mock.calls[0][0])).toBe(
      'https://identity.example.com/oauth2/consent?login_id=bound%2Flogin',
    )
    expect(fetch.mock.calls[0][1]?.method).toBe('GET')
    expect(fetch).toHaveBeenCalledTimes(1)
  })

  it.each(['approve', 'deny'] as const)('submits %s using only the bound login and CSRF', async (decision) => {
    const fetch = vi.fn<typeof globalThis.fetch>().mockResolvedValue(jsonResponse({ status: 'approved' }))
    vi.stubGlobal('fetch', fetch)

    await decideDeviceVerification('bound-login', decision, 'decision-csrf')
    const [url, init] = fetch.mock.calls[0]
    expect(String(url)).toBe('https://identity.example.com/oauth2/consent')
    expect(init?.method).toBe('POST')
    expect(new Headers(init?.headers).get('x-csrf-token')).toBe('decision-csrf')
    expect(JSON.parse(String(init?.body))).toEqual({ login_id: 'bound-login', decision })
  })

  it('keeps decision errors on the same interaction for retry, never the consumed code', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(businessError(500, 26012)))
    await expect(decideDeviceVerification('bound/login', 'approve', 'csrf')).rejects.toThrow()
    expect(deviceInteractionPath('bound/login', 'zh-CN en-US'))
      .toBe('/device?login_id=bound%2Flogin&ui_locales=zh-CN+en-US')
  })

  it('does not restart login or mark the entry field invalid on a bound lookup failure', async () => {
    const fetch = vi.fn().mockResolvedValue(businessError(422, 26010))
    vi.stubGlobal('fetch', fetch)
    expect((await loadDeviceVerification('bound-login', 'en-US')).status).toBe('failed')
    expect(fetch).toHaveBeenCalledTimes(1)
  })
})

function jsonResponse(payload: unknown, status = 200) {
  return new Response(JSON.stringify(payload), {
    status,
    headers: { 'content-type': 'application/json' },
  })
}

function businessError(status: number, code: number) {
  return jsonResponse({ error: { code, message: `Identity error ${code}`, fields: [] } }, status)
}
