import { beforeEach, describe, expect, it, vi } from 'vitest'

import { AccountSessionExpiredError, GraphqlRequestError } from './graphql.server'
import { executeAccountAction } from './account-action.server'

const mocks = vi.hoisted(() => ({
  clearElevatedAuthorization: vi.fn(),
  clearMfaUiState: vi.fn(),
  completeTotpStateChange: vi.fn(),
  finishLogout: vi.fn(),
  getRequestHeader: vi.fn(),
  identityGraphql: vi.fn(),
  preflightIdentityGraphql: vi.fn(),
  loadApplicationUrl: vi.fn(),
  mfaUiState: vi.fn(),
  requestLocale: vi.fn(),
  storeAccountFlash: vi.fn(),
  storeMfaEnrollment: vi.fn(),
  storeRegeneratedRecoveryCodes: vi.fn(),
  storeTotpEnabled: vi.fn(),
  restartAccountSignIn: vi.fn(),
  startAccountSwitch: vi.fn(),
  startPopupReauthorization: vi.fn(),
  restartPopupReauthorization: vi.fn(),
}))

vi.mock('@tanstack/react-start/server', () => ({
  getRequestHeader: mocks.getRequestHeader,
}))

vi.mock('./runtime-config.server', () => ({
  loadApplicationUrl: mocks.loadApplicationUrl,
}))

vi.mock('./graphql.server', async (importOriginal) => ({
  ...(await importOriginal<typeof import('./graphql.server')>()),
  identityGraphql: mocks.identityGraphql,
  preflightIdentityGraphql: mocks.preflightIdentityGraphql,
}))

vi.mock('./i18n.server', () => ({
  requestLocale: mocks.requestLocale,
}))

vi.mock('./oauth.server', () => ({
  clearElevatedAuthorization: mocks.clearElevatedAuthorization,
  clearMfaUiState: mocks.clearMfaUiState,
  completeTotpStateChange: mocks.completeTotpStateChange,
  finishLogout: mocks.finishLogout,
  mfaUiState: mocks.mfaUiState,
  storeMfaEnrollment: mocks.storeMfaEnrollment,
  storeRegeneratedRecoveryCodes: mocks.storeRegeneratedRecoveryCodes,
  storeTotpEnabled: mocks.storeTotpEnabled,
  restartAccountSignIn: mocks.restartAccountSignIn,
  startAccountSwitch: mocks.startAccountSwitch,
  startPopupReauthorization: mocks.startPopupReauthorization,
  restartPopupReauthorization: mocks.restartPopupReauthorization,
}))

vi.mock('./oauth-session.server', () => ({
  storeAccountFlash: mocks.storeAccountFlash,
}))

beforeEach(() => {
  vi.clearAllMocks()
  mocks.getRequestHeader.mockReturnValue(undefined)
  mocks.loadApplicationUrl.mockReturnValue('https://login.example.com')
  mocks.requestLocale.mockReturnValue('en-US')
  mocks.identityGraphql.mockResolvedValue({ changed: true, account: { username: 'alice' } })
  mocks.restartAccountSignIn.mockResolvedValue(new URL('https://identity.example.com/oauth2/authorize?state=signin'))
  mocks.preflightIdentityGraphql.mockReset().mockResolvedValue(undefined)
  mocks.mfaUiState.mockResolvedValue({})
  mocks.finishLogout.mockResolvedValue(new Response(null, {
    status: 303,
    headers: { location: 'https://identity.example.com/oauth2/logout' },
  }))
  mocks.startPopupReauthorization.mockResolvedValue({
    url: 'https://identity.example.com/oauth2/authorize?state=new',
    state: 'new',
  })
  mocks.startAccountSwitch.mockResolvedValue(new Response(null, {
    status: 302,
    headers: { location: 'https://identity.example.com/oauth2/authorize?prompt=select_account&state=new' },
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
        new_password: 'new-password',
        confirm_password: 'different-password',
      },
    })).resolves.toEqual({ ok: false })

    expect(mocks.identityGraphql).not.toHaveBeenCalled()
    expect(mocks.storeAccountFlash).toHaveBeenCalledWith(expect.objectContaining({
      fields: { confirm_password: expect.any(String) },
    }))
  })

  it('normalizes empty profile values and supports clearing appearance preferences', async () => {
    await expect(executeAccountAction({
      action: 'update-profile',
      values: {
        given_name: ' Alice ',
        family_name: ' ',
        nickname: '',
        website: ' https://example.com ',
        birthdate: '',
        locale: 'browser',
        theme: 'system',
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
          theme: null,
        },
      },
      undefined,
    )
  })

  it.each([
    ['Asia/Shanghai', 'Asia/Shanghai'],
    ['browser', null],
    ['', null],
  ] as const)('sends a sparse zoneInfo for %s', async (zone, expected) => {
    await expect(executeAccountAction({
      action: 'update-profile',
      values: { zone_info: zone },
    })).resolves.toEqual({ ok: true })

    expect(mocks.identityGraphql).toHaveBeenCalledWith(
      expect.stringContaining('mutation UpdateProfile'),
      { input: expect.objectContaining({ zoneInfo: expected }) },
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

  it('checks authentication freshness before confirming MFA enrollment', async () => {
    mocks.identityGraphql.mockRejectedValueOnce(new GraphqlRequestError([{ message: 'step up', extensions: { code: 'insufficient_user_authentication' } }], { acrValues: 'aal1', maxAge: 300 }))

    mocks.mfaUiState.mockResolvedValue({ enrollment: { enrollment_token: 'sealed-enrollment' } })
    const result = await executeAccountAction({
      action: 'confirm-totp',
      values: { code: '123456', login_hint: 'alice' },
    })

    expect(result.redirect).toBeUndefined()
    expect(result.reauth).toEqual({
      url: 'https://identity.example.com/oauth2/authorize?state=new',
      state: 'new',
    })
    expect(mocks.startPopupReauthorization).toHaveBeenCalledWith(
      '/account/security?setup=mfa&step=verify',
      'account',
      {
        loginHint: 'alice',
        acrValues: 'aal1',
        maxAge: 300,
      },
    )
    expect(mocks.mfaUiState).toHaveBeenCalledOnce()
    expect(mocks.identityGraphql).toHaveBeenCalledTimes(2)
    expect(mocks.identityGraphql).toHaveBeenLastCalledWith(expect.stringContaining('query ReauthenticationLoginHint'))
  })

  it('records TOTP as enabled when enrollment succeeds', async () => {
    mocks.mfaUiState.mockResolvedValue({
      enrollment: {
        enrollment_token: 'enrollment-token',
      },
    })

    await expect(executeAccountAction({
      action: 'confirm-totp',
      values: { code: '123456' },
    })).resolves.toEqual({ ok: true })

    expect(mocks.completeTotpStateChange).toHaveBeenCalledWith(true)
    expect(mocks.clearMfaUiState).not.toHaveBeenCalled()
  })

  it('propagates RFC 9470 requirements into the reauthentication redirect', async () => {
    mocks.identityGraphql
      .mockRejectedValueOnce(new GraphqlRequestError(
        [{
          message: 'recent authentication is required',
          extensions: { code: 'insufficient_user_authentication' },
        }],
        { acrValues: 'aal1', maxAge: 300 },
      ))
      .mockResolvedValueOnce({ account: { username: 'alice' } })

    const result = await executeAccountAction({ action: 'begin-totp', values: {} })
    expect(result.reauth).toEqual({
      url: 'https://identity.example.com/oauth2/authorize?state=new',
      state: 'new',
    })
    expect(mocks.startPopupReauthorization).toHaveBeenCalledWith(
      '/account/mfa/setup',
      'account',
      {
        loginHint: 'alice',
        acrValues: 'aal1',
        maxAge: 300,
      },
    )
    expect(mocks.identityGraphql).toHaveBeenNthCalledWith(
      2,
      expect.stringContaining('query ReauthenticationLoginHint'),
    )
    expect(mocks.storeAccountFlash).not.toHaveBeenCalled()
  })

  it.each([
    ['prepare-change-password', 'changePassword'],
    ['prepare-disable-totp', 'disableTotp'],
  ])('prechecks %s using the selected API without submitting it', async (action, field) => {
    expect(await executeAccountAction({ action, values: {} })).toEqual({ ok: true })
    expect(mocks.preflightIdentityGraphql).toHaveBeenCalledExactlyOnceWith(
      expect.stringContaining(field), undefined, { authorization: 'elevated' },
    )
    expect(mocks.identityGraphql).not.toHaveBeenCalled()
    expect(mocks.storeAccountFlash).not.toHaveBeenCalled()
  })

  it('honors the directive-derived challenge instead of a submitted assurance flag', async () => {
    mocks.preflightIdentityGraphql.mockRejectedValueOnce(new GraphqlRequestError([
      { message: 'step up', extensions: { code: 'insufficient_user_authentication' } },
    ], { acrValues: 'aal2', maxAge: 3600 }))
    const result = await executeAccountAction({
      action: 'prepare-change-password', values: { requires_aal2: 'false', login_hint: 'alice' },
    })
    expect(result.reauth).toBeTruthy()
    expect(mocks.startPopupReauthorization).toHaveBeenCalledWith(
      '/account/security?confirm=change-password', 'password', { loginHint: 'alice', acrValues: 'aal2', maxAge: 3600 },
    )
    expect(mocks.identityGraphql).toHaveBeenCalledExactlyOnceWith(expect.stringContaining('query ReauthenticationLoginHint'))
  })

  it('keeps the password scope when starting AAL2 password reauthentication', async () => {
    mocks.preflightIdentityGraphql.mockRejectedValueOnce(new GraphqlRequestError([{ message: 'step up', extensions: { code: 'insufficient_user_authentication' } }], { acrValues: 'aal2', maxAge: 3600 }))

    const result = await executeAccountAction({
      action: 'prepare-change-password',
      values: { login_hint: 'alice' },
    })

    expect(result.reauth).toEqual({
      url: 'https://identity.example.com/oauth2/authorize?state=new',
      state: 'new',
    })
    expect(mocks.startPopupReauthorization).toHaveBeenCalledWith(
      '/account/security?confirm=change-password',
      'password',
      {
        loginHint: 'alice',
        acrValues: 'aal2',
        maxAge: 3600,
      },
    )
  })

  it('changes a password without sending the current password', async () => {
    await expect(executeAccountAction({
      action: 'change-password',
      values: {
        new_password: 'a-new-password',
        confirm_password: 'a-new-password',
      },
    })).resolves.toEqual({ ok: true })

    expect(mocks.identityGraphql).toHaveBeenCalledWith(
      expect.stringContaining('mutation ChangePassword'),
      { input: { newPassword: 'a-new-password' } },
      { authorization: 'elevated' },
    )
  })

  it('starts reauthentication locally when the token is not fresh', async () => {
    mocks.preflightIdentityGraphql.mockRejectedValueOnce(new GraphqlRequestError([{ message: 'step up', extensions: { code: 'insufficient_user_authentication' } }], { acrValues: 'aal2', maxAge: 3600 }))

    const result = await executeAccountAction({
      action: 'prepare-disable-totp',
      values: { login_hint: 'alice' },
    })

    expect(result.reauth).toEqual({
      url: 'https://identity.example.com/oauth2/authorize?state=new',
      state: 'new',
    })
    expect(mocks.startPopupReauthorization).toHaveBeenCalledWith(
      '/account/security?confirm=disable-mfa',
      'mfa',
      {
        loginHint: 'alice',
        acrValues: 'aal2',
        maxAge: 3600,
      },
    )
    expect(mocks.identityGraphql).toHaveBeenCalledExactlyOnceWith(expect.stringContaining('query ReauthenticationLoginHint'))
  })

  it('requires fresh AAL2 before regenerating recovery codes', async () => {
    mocks.identityGraphql.mockRejectedValueOnce(new GraphqlRequestError([{ message: 'step up', extensions: { code: 'insufficient_user_authentication' } }], { acrValues: 'aal2', maxAge: 3600 }))

    const result = await executeAccountAction({
      action: 'regenerate-recovery-codes',
      values: { login_hint: 'alice' },
    })

    expect(result.reauth).toEqual({
      url: 'https://identity.example.com/oauth2/authorize?state=new',
      state: 'new',
    })
    expect(mocks.startPopupReauthorization).toHaveBeenCalledWith(
      '/account/security?confirm=recovery-codes',
      'mfa',
      {
        loginHint: 'alice',
        acrValues: 'aal2',
        maxAge: 3600,
      },
    )
    expect(mocks.identityGraphql).toHaveBeenCalledTimes(2)
    expect(mocks.identityGraphql).toHaveBeenLastCalledWith(expect.stringContaining('query ReauthenticationLoginHint'))
  })

  it('stores newly generated recovery codes for their one-time display', async () => {
    mocks.identityGraphql.mockResolvedValue({
      regenerateRecoveryCodes: {
        recoveryCodes: ['NEWA-CODE', 'NEWB-CODE'],
      },
    })

    await expect(executeAccountAction({
      action: 'regenerate-recovery-codes',
      values: { login_hint: 'alice' },
    })).resolves.toEqual({ ok: true })

    expect(mocks.identityGraphql).toHaveBeenCalledWith(
      expect.stringContaining('mutation RegenerateRecoveryCodes'),
      undefined,
      { authorization: 'elevated' },
    )
    expect(mocks.storeRegeneratedRecoveryCodes).toHaveBeenCalledWith([
      'NEWA-CODE',
      'NEWB-CODE',
    ])
    expect(mocks.clearElevatedAuthorization).toHaveBeenCalledOnce()
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

  it('restarts only the sealed popup reauthentication state', async () => {
    mocks.restartPopupReauthorization.mockResolvedValue({
      url: 'https://identity.example.com/oauth2/authorize?state=retry',
      state: 'retry',
    })

    await expect(executeAccountAction({
      action: 'retry-reauthentication',
      values: { state: 'pending-state' },
    })).resolves.toEqual({
      reauth: {
        url: 'https://identity.example.com/oauth2/authorize?state=retry',
        state: 'retry',
      },
    })
    expect(mocks.restartPopupReauthorization).toHaveBeenCalledWith('pending-state')
  })

  it('reports an expired reauthentication retry without a new request', async () => {
    mocks.restartPopupReauthorization.mockResolvedValue(undefined)

    await expect(executeAccountAction({
      action: 'retry-reauthentication',
      values: { state: 'expired-state' },
    })).resolves.toEqual({ ok: false })
  })

  it('returns the provider logout redirect', async () => {
    await expect(executeAccountAction({ action: 'logout', values: {} }))
      .resolves.toEqual({ redirect: 'https://identity.example.com/oauth2/logout' })

    expect(mocks.finishLogout).toHaveBeenCalledWith('https://login.example.com')
  })

  it('starts a prompt-based normal sign-in when switching accounts', async () => {
    await expect(executeAccountAction({
      action: 'switch-account',
      values: { login_hint: 'must-not-be-used' },
    })).resolves.toEqual({
      redirect: 'https://identity.example.com/oauth2/authorize?prompt=select_account&state=new',
    })

    expect(mocks.startAccountSwitch).toHaveBeenCalledWith('/account/profile')
    expect(mocks.startPopupReauthorization).not.toHaveBeenCalled()
    expect(mocks.finishLogout).not.toHaveBeenCalled()
  })

  it.each(['passkey', 'otp'])('sends only the %s preference mutation without requesting reauthentication', async (method) => {
    await expect(executeAccountAction({ action: 'update-mfa-preference', values: { preferred_mfa_method: method } })).resolves.toEqual({ ok: true })
    expect(mocks.identityGraphql).toHaveBeenCalledExactlyOnceWith(
      expect.stringContaining('mutation UpdateMfaPreference'),
      { method: method.toUpperCase() },
      undefined,
    )
    expect(mocks.preflightIdentityGraphql).not.toHaveBeenCalled()
    expect(mocks.startPopupReauthorization).not.toHaveBeenCalled()
  })

  it('rejects an unsupported MFA preference without sending a mutation', async () => {
    expect(await executeAccountAction({ action: 'update-mfa-preference', values: { preferred_mfa_method: 'password-only' } })).toEqual({ ok: false })
    expect(mocks.identityGraphql).not.toHaveBeenCalled()
  })

})

it('prepares authentication for a browser-prechecked action without submitting its mutation', async () => {
  mocks.preflightIdentityGraphql.mockResolvedValueOnce(undefined)
  expect(await executeAccountAction({ action: 'update-username', values: { login_hint: 'person' }, preflightOnly: true })).toEqual({ ok: true })
  expect(mocks.preflightIdentityGraphql).toHaveBeenCalledExactlyOnceWith(
    expect.stringContaining('mutation UpdateUsername'), undefined, { authorization: 'elevated' },
  )
  expect(mocks.identityGraphql).not.toHaveBeenCalled()
  expect(mocks.storeAccountFlash).not.toHaveBeenCalled()
})

it('returns a real challenge from a preflight-only request without executing the pending mutation', async () => {
  mocks.preflightIdentityGraphql.mockRejectedValueOnce(new GraphqlRequestError([
    { message: 'step up', extensions: { code: 'insufficient_user_authentication' } },
  ], { maxAge: 300 }))
  const result = await executeAccountAction({ action: 'update-username', values: { login_hint: 'person' }, preflightOnly: true })
  expect(result.reauth).toBeTruthy()
  expect(mocks.identityGraphql).toHaveBeenCalledExactlyOnceWith(expect.stringContaining('query ReauthenticationLoginHint'))
  expect(mocks.startPopupReauthorization).toHaveBeenCalledOnce()
})

it.each(['prepare-manage-passkeys'])('authorizes %s without creating a WebAuthn challenge or saving a preference', async (action) => {
  mocks.identityGraphql.mockResolvedValue({ prepareMfaManagement: true })
  expect(await executeAccountAction({ action, values: { login_hint: 'person' } })).toEqual({ ok: true })
  expect(mocks.identityGraphql).toHaveBeenCalledExactlyOnceWith(
    'mutation PrepareMfaManagement { prepareMfaManagement }', undefined, { authorization: 'elevated' },
  )
  expect(mocks.storeAccountFlash).not.toHaveBeenCalled()
})

it.each([
  ['prepare-manage-passkeys', 'passkeys'],
])('redirects %s to AAL2 before opening or changing settings', async (action, continuation) => {
  mocks.identityGraphql.mockRejectedValueOnce(new GraphqlRequestError([
    { message: 'step up', extensions: { code: 'insufficient_user_authentication' } },
  ], { acrValues: 'aal2', maxAge: 3600 }))
  const result = await executeAccountAction({ action, values: { login_hint: 'person', preferred_mfa_method: 'passkey' } })
  expect(result.reauth).toBeTruthy()
  expect(mocks.startPopupReauthorization).toHaveBeenCalledWith(
    `/account/security?confirm=${continuation}`, 'account', { loginHint: 'alice', acrValues: 'aal2', maxAge: 3600 },
  )
})

it.each([
  ['update-profile', '/account/profile'],
  ['change-password', '/account/security'],
  ['prepare-manage-passkeys', '/account/security'],
])('starts ordinary sign-in after %s loses its session', async (action, returnTo) => {
  mocks.identityGraphql.mockResolvedValueOnce(undefined)
  const result = await executeAccountAction({ action, values: {} })
  expect(result).toEqual({ redirect: 'https://identity.example.com/oauth2/authorize?state=signin' })
  expect(mocks.restartAccountSignIn).toHaveBeenCalledExactlyOnceWith(returnTo)
  expect(mocks.startPopupReauthorization).not.toHaveBeenCalled()
})

it('does not treat a missing preflight credential as an elevation request', async () => {
  mocks.preflightIdentityGraphql.mockRejectedValueOnce(new AccountSessionExpiredError())
  expect(await executeAccountAction({ action: 'update-username', values: { login_hint: 'stale-page' }, preflightOnly: true })).toHaveProperty('redirect')
  expect(mocks.restartAccountSignIn).toHaveBeenCalledWith('/account/identifiers')
  expect(mocks.startPopupReauthorization).not.toHaveBeenCalled()
})

it('checks live access even when a stale page supplies a login hint', async () => {
  mocks.preflightIdentityGraphql.mockRejectedValueOnce(new GraphqlRequestError([
    { message: 'freshness required', extensions: { code: 'insufficient_user_authentication' } },
  ], { acrValues: 'aal2', maxAge: 300 }))
  mocks.identityGraphql.mockResolvedValueOnce(undefined)
  expect(await executeAccountAction({ action: 'update-username', values: { login_hint: 'stale-page' }, preflightOnly: true })).toHaveProperty('redirect')
  expect(mocks.identityGraphql).toHaveBeenCalledExactlyOnceWith(expect.stringContaining('query ReauthenticationLoginHint'))
  expect(mocks.startPopupReauthorization).not.toHaveBeenCalled()
})

it('keeps permission denial separate from authentication recovery', async () => {
  mocks.identityGraphql.mockRejectedValueOnce(new GraphqlRequestError([
    { message: 'Permission denied', extensions: { code: 'insufficient_scope', requiredScope: 'account.update' } },
  ]))
  expect(await executeAccountAction({ action: 'update-username', values: { username: 'someone' } })).toEqual({ ok: false })
  expect(mocks.startPopupReauthorization).not.toHaveBeenCalled()
  expect(mocks.restartAccountSignIn).not.toHaveBeenCalled()
})

it('does not retry an elevation popup after the account session is lost', async () => {
  mocks.identityGraphql.mockResolvedValueOnce(undefined)
  expect(await executeAccountAction({ action: 'retry-reauthentication', values: { state: 'stale-state' } })).toHaveProperty('redirect')
  expect(mocks.restartPopupReauthorization).not.toHaveBeenCalled()
})

it('does not turn a failed live-session lookup into either a popup or a login redirect', async () => {
  mocks.preflightIdentityGraphql.mockRejectedValueOnce(new GraphqlRequestError([
    { message: 'freshness required', extensions: { code: 'insufficient_user_authentication' } },
  ], { maxAge: 300 }))
  mocks.identityGraphql.mockRejectedValueOnce(new GraphqlRequestError([{ message: 'Service unavailable' }]))
  expect(await executeAccountAction({ action: 'update-username', values: {}, preflightOnly: true })).toEqual({ ok: false })
  expect(mocks.startPopupReauthorization).not.toHaveBeenCalled()
  expect(mocks.restartAccountSignIn).not.toHaveBeenCalled()
})
