import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

const mocks = vi.hoisted(() => ({
  flow: {
    data: {
      state: 'expected-state',
      verifier: 'verifier',
      mode: 'signin' as 'signin' | 'reauth',
      return_to: '/',
      select_account: undefined as boolean | undefined,
      popup: undefined as boolean | undefined,
      reauth_purpose: undefined as 'password' | 'account' | 'mfa' | undefined,
      reauth_requirements: undefined as
        | { loginHint: string; acrValues?: string; maxAge?: number }
        | undefined,
    },
    clear: vi.fn(),
    update: vi.fn(),
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

import {
  accessToken,
  finishAuthorization,
  restartPopupReauthorization,
  restartAccountSignIn,
  startPopupReauthorization,
  startReauthorization,
  startSignIn,
  tokenSubject,
} from './oauth.server'

function token(claims: Record<string, unknown>) {
  return `header.${Buffer.from(JSON.stringify(claims)).toString('base64url')}.signature`
}

describe('refresh failure recovery', () => {
  afterEach(() => vi.unstubAllGlobals())

  it.each(['invalid_grant', 'server_error'])('starts a new sign-in after %s', async (oauthError) => {
    vi.clearAllMocks()
    mocks.getRequestHeader.mockReturnValue(undefined)
    mocks.authorization.data = {
      access_token: 'expired-access', refresh_token: 'old-refresh', expires_at: 0,
    }
    vi.stubGlobal('fetch', vi.fn(async () => Response.json({
      error: oauthError, error_description: 'Refresh failed',
    }, { status: oauthError === 'server_error' ? 500 : 400 })))

    await expect(accessToken()).resolves.toBeUndefined()
    expect(mocks.authorization.clear).toHaveBeenCalledOnce()
    expect(mocks.mfa.clear).toHaveBeenCalledOnce()
    expect(mocks.flash.clear).toHaveBeenCalledOnce()

    const location = await startSignIn('/account/security')
    expect(location.pathname).toBe('/oauth2/authorize')
    expect(location.searchParams.get('state')).toBeTruthy()
    expect(location.searchParams.get('code_challenge')).toBeTruthy()
    expect(location.searchParams.get('ui_locales')).toBeNull()
    expect(mocks.flow.update).toHaveBeenCalledWith(expect.objectContaining({
      mode: 'signin', return_to: '/account/security',
    }))
    mocks.authorization.data = {}
  })
})

describe('authorization request selection', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    mocks.getRequestHeader.mockReturnValue(undefined)
    mocks.flow.data.mode = 'signin'
    mocks.flow.data.return_to = '/'
    mocks.flow.data.select_account = undefined
  })

  it('asks for explicit account selection without a prior login hint', async () => {
    const location = await startSignIn('/account/profile', { selectAccount: true })
    expect(location.pathname).toBe('/oauth2/authorize')
    expect(location.searchParams.get('prompt')).toBe('select_account')
    expect(location.searchParams.get('login_hint')).toBeNull()
    expect(location.searchParams.get('max_age')).toBeNull()
    expect(mocks.flow.update).toHaveBeenCalledWith(expect.objectContaining({
      mode: 'signin',
      return_to: '/account/profile',
      select_account: true,
    }))
  })

  it('keeps ordinary sign-in prompt-free without selection state', async () => {
    const location = await startSignIn('/account/profile')
    expect(location.searchParams.get('prompt')).toBeNull()
    expect(location.searchParams.get('login_hint')).toBeNull()
    const stored = mocks.flow.update.mock.calls[0][0] as {
      mode: string
      return_to: string
      select_account?: boolean
    }
    expect(stored).toMatchObject({ mode: 'signin', return_to: '/account/profile' })
    expect(stored.select_account).toBeUndefined()
  })

  it('keeps reauthentication bound to its login hint and never selects an account', async () => {
    const response = await startReauthorization('/account/profile', 'account', {
      loginHint: 'alice',
    })
    const location = new URL(response.headers.get('location')!)
    expect(location.searchParams.get('prompt')).toBeNull()
    expect(location.searchParams.get('login_hint')).toBe('alice')
    expect(location.searchParams.get('max_age')).toBe('0')
    const stored = mocks.flow.update.mock.calls[0][0] as {
      mode: string
      select_account?: boolean
    }
    expect(stored.mode).toBe('reauth')
    expect(stored.select_account).toBeUndefined()
  })

  it('records the popup flag for account-center reauthentication only', async () => {
    const request = await startPopupReauthorization(
      '/account/security?confirm=change-password',
      'password',
      { loginHint: 'alice', acrValues: 'aal2', maxAge: 300 },
    )
    const location = new URL(request.url)

    expect(location.searchParams.get('state')).toBe(request.state)
    expect(location.searchParams.get('login_hint')).toBe('alice')
    expect(location.searchParams.get('acr_values')).toBe('aal2')
    expect(location.searchParams.get('max_age')).toBe('300')
    expect(location.searchParams.get('prompt')).toBeNull()
    expect(mocks.flow.update).toHaveBeenCalledWith(expect.objectContaining({
      mode: 'reauth',
      return_to: '/account/security?confirm=change-password',
      popup: true,
      reauth_requirements: {
        loginHint: 'alice',
        acrValues: 'aal2',
        maxAge: 300,
      },
    }))
  })

  it('never records the popup flag for an ordinary sign-in', async () => {
    await startSignIn('/account/profile')

    const stored = mocks.flow.update.mock.calls[0][0] as {
      mode: string
      popup?: boolean
    }
    expect(stored.mode).toBe('signin')
    expect(stored.popup).toBeUndefined()
  })
})

describe('popup reauthentication retry', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    mocks.getRequestHeader.mockReturnValue(undefined)
    mocks.flow.data.mode = 'reauth'
    mocks.flow.data.return_to = '/account/security?confirm=passkeys'
    mocks.flow.data.popup = true
    mocks.flow.data.reauth_requirements = {
      loginHint: 'alice',
      acrValues: 'aal2',
      maxAge: 300,
    }
  })

  it('starts a fresh popup request only for the sealed pending state', async () => {
    const request = await restartPopupReauthorization('expected-state')

    expect(request).toBeDefined()
    const location = new URL(request!.url)
    expect(location.searchParams.get('state')).not.toBe('expected-state')
    expect(location.searchParams.get('login_hint')).toBe('alice')
    expect(location.searchParams.get('acr_values')).toBe('aal2')
    expect(location.searchParams.get('max_age')).toBe('300')
    expect(mocks.flow.update).toHaveBeenCalledWith(expect.objectContaining({
      mode: 'reauth',
      return_to: '/account/security?confirm=passkeys',
      popup: true,
    }))
  })

  it('refuses a state from a different request', async () => {
    await expect(restartPopupReauthorization('other-state')).resolves.toBeUndefined()
    expect(mocks.flow.update).not.toHaveBeenCalled()
  })
})

describe('token subjects', () => {
  it('reads the stable subject and ignores missing or malformed tokens', () => {
    expect(tokenSubject(token({ sub: 'user-1' }))).toBe('user-1')
    expect(tokenSubject(token({ sid: 'session-only' }))).toBeUndefined()
    expect(tokenSubject('not-a-token')).toBeUndefined()
    expect(tokenSubject(undefined)).toBeUndefined()
  })
})

describe('OAuth callback errors', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    vi.unstubAllGlobals()
    mocks.getRequestHeader.mockReturnValue(undefined)
    mocks.flow.data.mode = 'signin'
    mocks.flow.data.return_to = '/'
    mocks.flow.data.select_account = undefined
    mocks.flow.data.popup = undefined
    mocks.authorization.data = {}
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

  it('clears the previous elevated and account UI state after a successful switch', async () => {
    mocks.flow.data.select_account = true
    mocks.flow.data.return_to = '/account/profile'
    vi.stubGlobal('fetch', vi.fn(async () => new Response(JSON.stringify({
      access_token: 'new-access',
      refresh_token: 'new-refresh',
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
      'https://identity.example/account/profile',
    )
    expect(mocks.mfa.clear).toHaveBeenCalledOnce()
    expect(mocks.flash.clear).toHaveBeenCalledOnce()
    expect(mocks.authorization.update).toHaveBeenCalledWith(expect.objectContaining({
      access_token: 'new-access',
      elevated_access_token: undefined,
      elevated_expires_at: undefined,
    }))
  })

  it('keeps the previous usable account when an account switch is canceled', async () => {
    mocks.flow.data.select_account = true

    const response = await finishAuthorization(
      new Request(
        'https://identity.example/callback?error=access_denied&state=expected-state',
      ),
    )

    expect(response.status).toBe(302)
    expect(mocks.flow.clear).toHaveBeenCalledOnce()
    // Nothing of the old account is withdrawn before a successful switch.
    expect(mocks.authorization.clear).not.toHaveBeenCalled()
    expect(mocks.mfa.clear).not.toHaveBeenCalled()
    expect(mocks.flash.clear).not.toHaveBeenCalled()
  })

  it('opens the password form after reauthentication without a resubmit notice', async () => {
    mocks.flow.data.mode = 'reauth'
    mocks.flow.data.return_to = '/account/security?confirm=change-password'
    mocks.authorization.data = { access_token: token({ sub: 'user' }) }
    vi.stubGlobal('fetch', vi.fn(async () => new Response(JSON.stringify({
      access_token: 'elevated-token',
      id_token: token({ sub: 'user' }),
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

describe('popup reauthentication callback', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    vi.unstubAllGlobals()
    mocks.getRequestHeader.mockReturnValue(undefined)
    mocks.flow.data.mode = 'reauth'
    mocks.flow.data.return_to = '/account/security?confirm=change-password'
    mocks.flow.data.popup = true
    mocks.flow.data.select_account = undefined
    mocks.authorization.data = { access_token: token({ sub: 'user' }) }
  })

  afterEach(() => vi.unstubAllGlobals())

  it('answers the same-origin frame with state and result but no tokens', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => Response.json({
      access_token: 'elevated-token',
      refresh_token: 'private-refresh-token',
      id_token: token({ sub: 'user' }),
      expires_in: 3600,
    })))

    const response = await finishAuthorization(
      new Request(
        'https://identity.example/callback?code=authorization-code&state=expected-state',
      ),
    )
    const html = await response.text()

    expect(response.status).toBe(200)
    expect(response.headers.get('location')).toBeNull()
    expect(response.headers.get('cache-control')).toBe('no-store')
    expect(html).toContain('identity.account-reauth')
    expect(html).toContain('"state":"expected-state"')
    expect(html).toContain('"returnTo":"/account/security?confirm=change-password"')
    expect(html).toContain('"result":"success"')
    expect(html).toContain('"https://identity.example"')
    expect(html).not.toContain('elevated-token')
    expect(html).not.toContain('private-refresh-token')
    expect(html).not.toContain('authorization-code')
    expect(mocks.authorization.update).toHaveBeenCalledWith({
      elevated_access_token: 'elevated-token',
      elevated_expires_at: expect.any(Number),
    })
  })

  it('rejects a token for a different subject and preserves the current account', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => Response.json({
      access_token: 'other-account-token',
      id_token: token({ sub: 'mallory' }),
      expires_in: 3600,
    })))

    const response = await finishAuthorization(
      new Request(
        'https://identity.example/callback?code=authorization-code&state=expected-state',
      ),
    )
    const html = await response.text()

    expect(response.status).toBe(200)
    expect(response.headers.get('location')).toBeNull()
    expect(html).toContain('"result":"error"')
    expect(html).not.toContain('other-account-token')
    expect(mocks.authorization.clear).not.toHaveBeenCalled()
    // The sealed retry parameters stay available and no new elevation is stored.
    expect(mocks.flow.clear).not.toHaveBeenCalled()
    expect(mocks.authorization.update).not.toHaveBeenCalled()
  })

  it('posts a cancellation result when the provider reports access_denied', async () => {
    const response = await finishAuthorization(
      new Request(
        'https://identity.example/callback?error=access_denied&state=expected-state',
      ),
    )
    const html = await response.text()

    expect(html).toContain('"result":"cancelled"')
    expect(mocks.authorization.clear).not.toHaveBeenCalled()
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
    mocks.flow.data.select_account = undefined
    mocks.flow.data.popup = undefined
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
    mocks.authorization.data = { access_token: token({ sub: 'user' }) }
    vi.stubGlobal('fetch', vi.fn(async () => new Response(JSON.stringify({
      access_token: 'elevated-token',
      id_token: token({ sid: 'protected-session', sub: 'user' }),
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

it('clears rejected credentials and starts an ordinary account sign-in without elevation parameters', async () => {
  vi.clearAllMocks()
  mocks.getRequestHeader.mockReturnValue(undefined)
  const url = await restartAccountSignIn('/account/identifiers')
  expect(mocks.authorization.clear).toHaveBeenCalledOnce()
  expect(url.searchParams.has('prompt')).toBe(false)
  expect(url.searchParams.has('max_age')).toBe(false)
  expect(url.searchParams.has('login_hint')).toBe(false)
  expect(mocks.flow.update).toHaveBeenCalledWith(expect.objectContaining({ mode: 'signin', return_to: '/account/identifiers' }))
})
