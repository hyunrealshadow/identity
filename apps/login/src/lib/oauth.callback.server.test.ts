import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

const mocks = vi.hoisted(() => ({
  flow: {
    data: {
      state: 'expected-state',
      verifier: 'verifier',
      mode: 'signin' as 'signin' | 'reauth',
      return_to: '/',
    },
    clear: vi.fn(),
  },
  authorization: { data: {}, clear: vi.fn(), update: vi.fn() },
  mfa: { data: {}, clear: vi.fn(), update: vi.fn() },
  flash: { data: {}, clear: vi.fn(), update: vi.fn() },
  storeAccountFlash: vi.fn(),
  getRequestHeader: vi.fn(),
  setResponseHeader: vi.fn(),
}))

vi.mock('@tanstack/react-start/server', () => ({
  getRequestHeader: mocks.getRequestHeader,
  setResponseHeader: mocks.setResponseHeader,
}))

vi.mock('./runtime-config.server', () => ({
  loadOAuthClient: vi.fn(async () => ({
    client_id: 'client',
    client_secret: 'secret',
  })),
  loadApplicationUrl: vi.fn(() => 'https://identity.example/'),
}))

vi.mock('./i18n.server', () => ({
  requestLocale: vi.fn(() => 'en-US'),
}))

vi.mock('./oauth-session.server', () => ({
  useOAuthFlowSession: vi.fn(async () => mocks.flow),
  useAuthorizationSession: vi.fn(async () => mocks.authorization),
  useMfaUiSession: vi.fn(async () => mocks.mfa),
  useAccountFlashSession: vi.fn(async () => mocks.flash),
  storeAccountFlash: mocks.storeAccountFlash,
}))

import { finishAuthorization } from './oauth.server'

describe('OAuth callback errors', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    vi.unstubAllGlobals()
    mocks.getRequestHeader.mockReturnValue(undefined)
    mocks.flow.data.mode = 'signin'
    mocks.flow.data.return_to = '/'
  })

  it('discards a failed sign-in flow and redirects to the error page', async () => {
    const response = await finishAuthorization(
      new Request(
        'https://identity.example/callback?error=invalid_request&error_description=The+request+is+invalid.&state=expected-state',
      ),
    )

    expect(response.status).toBe(302)
    const location = new URL(response.headers.get('location')!)
    expect(location.pathname).toBe('/authorization-error')
    expect(location.searchParams.get('error')).toBe('invalid_request')
    expect(location.searchParams.get('error_description')).toBe(
      'The request is invalid.',
    )
    expect(mocks.flow.clear).toHaveBeenCalledOnce()
    expect(mocks.authorization.clear).toHaveBeenCalledOnce()
    expect(mocks.mfa.clear).toHaveBeenCalledOnce()
    expect(mocks.flash.clear).toHaveBeenCalledOnce()
  })

  it('keeps baseline authorization when reauthentication fails', async () => {
    mocks.flow.data.mode = 'reauth'

    await finishAuthorization(
      new Request(
        'https://identity.example/callback?error=access_denied&state=expected-state',
      ),
    )

    expect(mocks.authorization.clear).not.toHaveBeenCalled()
    expect(mocks.authorization.update).toHaveBeenCalledWith({
      elevated_access_token: undefined,
      elevated_expires_at: undefined,
    })
  })

  it('does not clear tokens for an untrusted state', async () => {
    const response = await finishAuthorization(
      new Request(
        'https://identity.example/callback?error=invalid_request&state=attacker-state',
      ),
    )

    expect(response.status).toBe(400)
    expect(mocks.flow.clear).not.toHaveBeenCalled()
    expect(mocks.authorization.clear).not.toHaveBeenCalled()
  })

  it('opens the password form after reauthentication without a resubmit notice', async () => {
    mocks.flow.data.mode = 'reauth'
    mocks.flow.data.return_to = '/account/security?confirm=change-password'
    vi.stubGlobal('fetch', vi.fn(async () => new Response(JSON.stringify({
      access_token: 'elevated-token',
      expires_in: 3600,
    }), {
      status: 200,
      headers: { 'content-type': 'application/json' },
    })))

    const response = await finishAuthorization(
      new Request(
        'https://identity.example/callback?code=authorization-code&state=expected-state',
      ),
    )

    expect(response.headers.get('location')).toBe(
      'https://identity.example/account/security?confirm=change-password',
    )
    expect(mocks.authorization.update).toHaveBeenCalledWith({
      elevated_access_token: 'elevated-token',
      elevated_expires_at: expect.any(Number),
    })
    expect(mocks.storeAccountFlash).not.toHaveBeenCalled()
  })
})

describe('login transport sync after a silent authorization', () => {
  const token = (claims: Record<string, unknown>) =>
    `header.${Buffer.from(JSON.stringify(claims)).toString('base64url')}.signature`

  const configuredCookie = (sessions: Array<string>) =>
    `identity.sessions=${encodeURIComponent(JSON.stringify(sessions))}`

  const signedIn = (idToken: string) =>
    vi.fn(async () => new Response(JSON.stringify({
      access_token: 'access-token',
      id_token: idToken,
      expires_in: 3600,
    }), {
      status: 200,
      headers: { 'content-type': 'application/json' },
    }))

  beforeEach(() => {
    vi.clearAllMocks()
    vi.unstubAllGlobals()
    mocks.getRequestHeader.mockReturnValue(undefined)
    mocks.flow.data.mode = 'signin'
    mocks.flow.data.return_to = '/device?user_code=WDJB-MJHT'
  })

  afterEach(() => {
    vi.unstubAllGlobals()
  })

  it('records the provider session the authorization came from', async () => {
    vi.stubGlobal('fetch', signedIn(token({ sid: 'protected-session' })))

    const response = await finishAuthorization(
      new Request(
        'https://identity.example/callback?code=authorization-code&state=expected-state',
      ),
    )

    // Without this cookie a browser whose provider session answered silently
    // would return with tokens but no session the interactions can present.
    const cookie = response.headers.get('set-cookie') ?? ''
    expect(cookie).toContain(configuredCookie(['protected-session']))
    expect(cookie).toContain('HttpOnly')
    expect(cookie).toContain('Secure')
    expect(cookie).toContain('SameSite=Lax')
  })

  it('appends the session after the ones the browser already presents', async () => {
    mocks.getRequestHeader.mockImplementation((name: string) =>
      name === 'cookie' ? configuredCookie(['older-session']) : undefined,
    )
    vi.stubGlobal('fetch', signedIn(token({ sid: 'protected-session' })))

    const response = await finishAuthorization(
      new Request(
        'https://identity.example/callback?code=authorization-code&state=expected-state',
      ),
    )

    // The order belongs to the backend (`sessions` from the API decides which
    // entry acts), so recording a session must not reorder the list.
    expect(response.headers.get('set-cookie')).toContain(
      configuredCookie(['older-session', 'protected-session']),
    )
  })

  it('does not rewrite the cookie when the session is already known', async () => {
    mocks.getRequestHeader.mockImplementation((name: string) =>
      name === 'cookie'
        ? configuredCookie(['older-session', 'protected-session'])
        : undefined,
    )
    vi.stubGlobal('fetch', signedIn(token({ sid: 'protected-session' })))

    const response = await finishAuthorization(
      new Request(
        'https://identity.example/callback?code=authorization-code&state=expected-state',
      ),
    )

    expect(response.headers.get('set-cookie')).toBeNull()
  })

  it('does not rewrite the cookie when the authorization adds no session', async () => {
    vi.stubGlobal('fetch', signedIn(token({ sub: 'user' })))

    const response = await finishAuthorization(
      new Request(
        'https://identity.example/callback?code=authorization-code&state=expected-state',
      ),
    )

    expect(response.headers.get('set-cookie')).toBeNull()
  })

  it('does not touch the login transport for a reauthentication', async () => {
    mocks.flow.data.mode = 'reauth'
    vi.stubGlobal('fetch', vi.fn(async () => new Response(JSON.stringify({
      access_token: 'elevated-token',
      id_token: token({ sid: 'protected-session' }),
      expires_in: 3600,
    }), {
      status: 200,
      headers: { 'content-type': 'application/json' },
    })))

    const response = await finishAuthorization(
      new Request(
        'https://identity.example/callback?code=authorization-code&state=expected-state',
      ),
    )

    expect(response.headers.get('set-cookie')).toBeNull()
  })
})
