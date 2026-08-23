import { beforeEach, describe, expect, it, vi } from 'vitest'

import { GraphqlRequestError } from './graphql.server'
import { executeAccountAction } from './account-action.server'

const mocks = vi.hoisted(() => ({
  clearElevatedAuthorization: vi.fn(),
  clearMfaUiState: vi.fn(),
  finishLogout: vi.fn(),
  getRequestHeader: vi.fn(),
  identityGraphql: vi.fn(),
  loadClientCredentials: vi.fn(),
  mfaUiState: vi.fn(),
  requestLocale: vi.fn(),
  storeAccountFlash: vi.fn(),
  storeMfaEnrollment: vi.fn(),
  startReauthorization: vi.fn(),
}))

vi.mock('@tanstack/react-start/server', () => ({
  getRequestHeader: mocks.getRequestHeader,
}))

vi.mock('./client-credentials.server', () => ({
  loadClientCredentials: mocks.loadClientCredentials,
}))

vi.mock('./graphql.server', async (importOriginal) => ({
  ...(await importOriginal<typeof import('./graphql.server')>()),
  identityGraphql: mocks.identityGraphql,
}))

vi.mock('./i18n.server', () => ({
  requestLocale: mocks.requestLocale,
}))

vi.mock('./oauth.server', () => ({
  clearElevatedAuthorization: mocks.clearElevatedAuthorization,
  clearMfaUiState: mocks.clearMfaUiState,
  finishLogout: mocks.finishLogout,
  mfaUiState: mocks.mfaUiState,
  storeMfaEnrollment: mocks.storeMfaEnrollment,
  startReauthorization: mocks.startReauthorization,
}))

vi.mock('./oauth-session.server', () => ({
  storeAccountFlash: mocks.storeAccountFlash,
}))

beforeEach(() => {
  vi.clearAllMocks()
  mocks.getRequestHeader.mockReturnValue(undefined)
  mocks.loadClientCredentials.mockResolvedValue({
    application_url: 'https://login.example.com',
    client_id: 'client',
    client_secret: 'secret',
  })
  mocks.requestLocale.mockReturnValue('en-US')
  mocks.identityGraphql.mockResolvedValue({ changed: true })
  mocks.mfaUiState.mockResolvedValue({})
  mocks.finishLogout.mockResolvedValue(new Response(null, {
    status: 303,
    headers: { location: 'https://identity.example.com/oauth2/logout' },
  }))
  mocks.startReauthorization.mockResolvedValue(new Response(null, {
    status: 302,
    headers: { location: 'https://identity.example.com/oauth2/authorize?state=new' },
  }))
})

describe('executeAccountAction', () => {
  it('rejects a cross-origin account mutation before contacting GraphQL', async () => {
    mocks.getRequestHeader.mockReturnValue('https://attacker.example')

    await expect(executeAccountAction({
      action: 'revoke-others',
      values: {},
    })).resolves.toEqual({ ok: false })

    expect(mocks.identityGraphql).not.toHaveBeenCalled()
    expect(mocks.storeAccountFlash).toHaveBeenCalledWith(expect.objectContaining({
      error: expect.any(String),
    }))
  })

  it('reports a password confirmation mismatch without sending the password', async () => {
    await expect(executeAccountAction({
      action: 'change-password',
      values: {
        current_password: 'old-password',
        new_password: 'new-password',
        confirm_password: 'different-password',
      },
    })).resolves.toEqual({ ok: false })

    expect(mocks.identityGraphql).not.toHaveBeenCalled()
    expect(mocks.storeAccountFlash).toHaveBeenCalledWith(expect.objectContaining({
      fields: { confirm_password: expect.any(String) },
    }))
  })

  it('normalizes empty profile values and supports clearing the locale preference', async () => {
    await expect(executeAccountAction({
      action: 'update-profile',
      values: {
        given_name: ' Alice ',
        family_name: ' ',
        nickname: '',
        website: ' https://example.com ',
        birthdate: '',
        locale: 'browser',
      },
    })).resolves.toEqual({ ok: true })

    expect(mocks.identityGraphql).toHaveBeenCalledWith(
      expect.stringContaining('mutation UpdateProfile'),
      {
        input: {
          givenName: 'Alice',
          familyName: null,
          nickname: null,
          website: 'https://example.com',
          birthdate: null,
          locale: null,
        },
      },
      undefined,
    )
  })

  it('stores the pending MFA enrollment returned by GraphQL', async () => {
    mocks.identityGraphql.mockResolvedValue({
      beginTotpEnrollment: {
        secret: 'BASE32SECRET',
        otpAuthUri: 'otpauth://totp/Identity:user?algorithm=SHA256',
        enrollmentToken: 'protected-enrollment',
        recoveryCodes: ['AAAA-BBBB'],
      },
    })

    await expect(executeAccountAction({ action: 'begin-totp', values: {} }))
      .resolves.toEqual({ ok: true })

    expect(mocks.storeMfaEnrollment).toHaveBeenCalledWith({
      secret: 'BASE32SECRET',
      otp_auth_uri: 'otpauth://totp/Identity:user?algorithm=SHA256',
      enrollment_token: 'protected-enrollment',
      recovery_codes: ['AAAA-BBBB'],
    })
  })

  it('switches a pending MFA enrollment to SHA-1 without replacing its secret or recovery codes', async () => {
    mocks.mfaUiState.mockResolvedValue({
      enrollment: {
        secret: 'SAME-BASE32-SECRET',
        otp_auth_uri: 'otpauth://totp/Identity:user?algorithm=SHA256',
        enrollment_token: 'sha256-enrollment',
        recovery_codes: ['SAME-RECOVERY-CODE'],
      },
    })
    mocks.identityGraphql.mockResolvedValue({
      changeTotpEnrollmentAlgorithm: {
        secret: 'SAME-BASE32-SECRET',
        otpAuthUri: 'otpauth://totp/Identity:user?algorithm=SHA1',
        enrollmentToken: 'sha1-enrollment',
        recoveryCodes: ['SAME-RECOVERY-CODE'],
      },
    })

    await expect(executeAccountAction({ action: 'use-legacy-totp', values: {} }))
      .resolves.toEqual({ ok: true })

    expect(mocks.identityGraphql).toHaveBeenCalledWith(
      expect.stringContaining('mutation ChangeTotpEnrollmentAlgorithm'),
      {
        input: {
          enrollmentToken: 'sha256-enrollment',
          algorithm: 'SHA1',
        },
      },
      { authorization: 'elevated' },
    )
    expect(mocks.storeMfaEnrollment).toHaveBeenCalledWith({
      secret: 'SAME-BASE32-SECRET',
      otp_auth_uri: 'otpauth://totp/Identity:user?algorithm=SHA1',
      enrollment_token: 'sha1-enrollment',
      recovery_codes: ['SAME-RECOVERY-CODE'],
    })
    expect(mocks.storeAccountFlash).not.toHaveBeenCalled()
  })

  it('propagates RFC 9470 requirements into the reauthentication redirect', async () => {
    mocks.identityGraphql.mockRejectedValue(new GraphqlRequestError(
      [{
        message: 'recent authentication is required',
        extensions: { code: 'insufficient_user_authentication' },
      }],
      { acrValues: 'urn:identity:acr:aal1', maxAge: 300 },
    ))

    const result = await executeAccountAction({ action: 'begin-totp', values: {} })
    expect(result.redirect).toBe(
      'https://identity.example.com/oauth2/authorize?state=new',
    )
    expect(mocks.startReauthorization).toHaveBeenCalledWith(
      '/account/mfa/setup',
      'account',
      { acrValues: 'urn:identity:acr:aal1', maxAge: 300 },
    )
    expect(mocks.storeAccountFlash).not.toHaveBeenCalled()
  })

  it('updates a username independently and clears elevated authorization', async () => {
    await expect(executeAccountAction({
      action: 'update-username',
      values: { username: 'alice' },
    })).resolves.toEqual({ ok: true })

    expect(mocks.identityGraphql).toHaveBeenCalledWith(
      expect.stringContaining('mutation UpdateUsername'),
      { input: { username: 'alice' } },
      { authorization: 'elevated' },
    )
    expect(mocks.clearElevatedAuthorization).toHaveBeenCalledOnce()
  })

  it('updates an email independently and never sends the username', async () => {
    await expect(executeAccountAction({
      action: 'update-email',
      values: { email: 'alice@example.com' },
    })).resolves.toEqual({ ok: true })

    expect(mocks.identityGraphql).toHaveBeenCalledWith(
      expect.stringContaining('mutation UpdateEmail'),
      { input: { email: 'alice@example.com' } },
      { authorization: 'elevated' },
    )
    expect(mocks.clearElevatedAuthorization).toHaveBeenCalledOnce()
  })

  it('returns the provider logout redirect', async () => {
    await expect(executeAccountAction({ action: 'logout', values: {} }))
      .resolves.toEqual({ redirect: 'https://identity.example.com/oauth2/logout' })

    expect(mocks.finishLogout).toHaveBeenCalledWith('https://login.example.com')
  })

})
