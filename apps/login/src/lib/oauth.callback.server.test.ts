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
  storeAccountFlash: vi.fn(),
}))

import { finishAuthorization } from './oauth.server'

describe('OAuth callback errors', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    mocks.flow.data.mode = 'signin'
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
})
