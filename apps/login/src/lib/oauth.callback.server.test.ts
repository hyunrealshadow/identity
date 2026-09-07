import { beforeEach, describe, expect, it, vi } from 'vitest'

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
