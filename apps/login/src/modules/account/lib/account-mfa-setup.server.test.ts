import { beforeEach, describe, expect, it, vi } from 'vitest'

import {
  handleAccountMfaSetupGet,
  handleAccountMfaSetupPost,
} from '#/modules/account/lib/account-mfa-setup.server'

const mocks = vi.hoisted(() => ({
  identityGraphql: vi.fn(),
  loadApplicationUrl: vi.fn(),
  requestLocale: vi.fn(),
  restartAccountSignIn: vi.fn(),
  storeAccountFlash: vi.fn(),
  storeMfaEnrollment: vi.fn(),
}))

vi.mock('#/lib/graphql.server', async (original) => ({
  ...(await original<typeof import('#/lib/graphql.server')>()),
  identityGraphql: mocks.identityGraphql,
}))

vi.mock('#/lib/runtime-config.server', () => ({
  loadApplicationUrl: mocks.loadApplicationUrl,
}))

vi.mock('#/lib/i18n.server', () => ({
  requestLocale: mocks.requestLocale,
}))

vi.mock('#/lib/oauth.server', () => ({
  restartAccountSignIn: mocks.restartAccountSignIn,
  storeMfaEnrollment: mocks.storeMfaEnrollment,
}))

vi.mock('#/lib/oauth-session.server', () => ({
  storeAccountFlash: mocks.storeAccountFlash,
}))

beforeEach(() => {
  vi.clearAllMocks()
  mocks.loadApplicationUrl.mockReturnValue('https://login.example.com')
  mocks.requestLocale.mockReturnValue('en-US')
  mocks.restartAccountSignIn.mockResolvedValue(new URL('https://issuer.example/authorize'))
  mocks.identityGraphql.mockResolvedValue({
    beginTotpEnrollment: {
      secret: 'BASE32SECRET',
      otpAuthUri: 'otpauth://totp/Identity:alice',
      enrollmentToken: 'enroll-token',
      recoveryCodes: ['CODE-1'],
    },
  })
})

describe('account MFA setup handler', () => {
  it('redirects on GET without executing any mutation or storing enrollment state', async () => {
    const response = await handleAccountMfaSetupGet()

    expect(response.status).toBe(303)
    expect(response.headers.get('location')).toBe('/account/security?setup=mfa')
    expect(mocks.identityGraphql).not.toHaveBeenCalled()
    expect(mocks.storeMfaEnrollment).not.toHaveBeenCalled()
    expect(mocks.storeAccountFlash).not.toHaveBeenCalled()
  })

  it('rejects POST requests with a missing or cross-origin Origin header', async () => {
    for (const headers of [
      undefined,
      { origin: 'https://attacker.example' },
    ]) {
      const response = await handleAccountMfaSetupPost(
        new Request('https://login.example.com/account/mfa/setup', {
          method: 'POST',
          headers,
        }),
      )
      expect(response.status).toBe(303)
      expect(response.headers.get('location')).toBe('/account/security?setup=mfa')
    }

    expect(mocks.identityGraphql).not.toHaveBeenCalled()
    expect(mocks.storeMfaEnrollment).not.toHaveBeenCalled()
    expect(mocks.storeAccountFlash).toHaveBeenCalledTimes(2)
  })

  it('begins TOTP enrollment on same-origin POST and stores the enrollment payload', async () => {
    const response = await handleAccountMfaSetupPost(
      new Request('https://login.example.com/account/mfa/setup', {
        method: 'POST',
        headers: { origin: 'https://login.example.com' },
      }),
    )

    expect(response.status).toBe(303)
    expect(response.headers.get('location')).toBe('/account/security?setup=mfa')
    expect(mocks.identityGraphql).toHaveBeenCalledOnce()
    expect(mocks.storeMfaEnrollment).toHaveBeenCalledWith({
      secret: 'BASE32SECRET',
      otp_auth_uri: 'otpauth://totp/Identity:alice',
      enrollment_token: 'enroll-token',
      recovery_codes: ['CODE-1'],
    })
    expect(mocks.storeAccountFlash).toHaveBeenCalledWith({ message: 'saved' })
  })
})
