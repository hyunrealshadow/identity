import { beforeEach, expect, it, vi } from 'vitest'

const mocks = vi.hoisted(() => ({ graphql: vi.fn(), reauthorize: vi.fn(), restart: vi.fn(), origin: vi.fn() }))
vi.mock('@tanstack/react-start/server', () => ({ getRequestHeader: mocks.origin }))
vi.mock('#/lib/graphql.server', async (original) => ({ ...await original<typeof import('#/lib/graphql.server')>(), identityGraphql: mocks.graphql }))
vi.mock('#/lib/oauth.server', () => ({ restartAccountSignIn: mocks.restart, startReauthorization: mocks.reauthorize }))
vi.mock('#/lib/runtime-config.server', () => ({ loadApplicationUrl: () => 'https://login.example.com' }))
vi.mock('#/lib/i18n.server', () => ({ requestLocale: () => 'en-US' }))

import { GraphqlRequestError } from '#/lib/graphql.server'
import { passkeyAccountAction } from '#/modules/passkey/lib/passkey-account.server'

beforeEach(() => {
  vi.clearAllMocks()
  mocks.origin.mockReturnValue('https://login.example.com')
  mocks.restart.mockResolvedValue(new URL('https://identity.example.com/oauth2/authorize?state=signin'))
})

it('rejects a cross-origin mutation before calling the backend', async () => {
  mocks.origin.mockReturnValue('https://other.example.com')
  expect(await passkeyAccountAction({ action: 'begin' })).toHaveProperty('error')
  expect(mocks.graphql).not.toHaveBeenCalled()
})

it('uses the authenticated account token to begin enrollment', async () => {
  const options = { challenge_id: 'challenge', public_key: { challenge: 'abc' } }
  mocks.graphql.mockResolvedValueOnce({ beginPasskeyRegistration: options })
  expect(await passkeyAccountAction({ action: 'begin' })).toEqual({ options })
  expect(mocks.graphql).toHaveBeenCalledWith('mutation BeginPasskeyRegistration($recoveryEnrollmentToken: String) { beginPasskeyRegistration(recoveryEnrollmentToken: $recoveryEnrollmentToken) }', { recoveryEnrollmentToken: undefined }, { authorization: 'elevated' })
})

it('passes the credential JSON to the authenticated completion mutation', async () => {
  mocks.graphql.mockResolvedValueOnce({ finishPasskeyRegistration: true })
  expect(await passkeyAccountAction({ action: 'finish', id: 'challenge', name: 'Laptop', credential: '{"id":"credential"}' })).toEqual({ ok: true })
  expect(mocks.graphql.mock.calls[0][1]).toEqual({ id: 'challenge', name: 'Laptop', credential: { id: 'credential' } })
})

it('binds reauthentication to the current account and honors AAL2', async () => {
  mocks.graphql.mockRejectedValueOnce(new GraphqlRequestError([{ message: 'step up', extensions: { kind: 'unauthorized', challenge: { error: 'insufficient_user_authentication' } } }], { acrValues: 'aal2', maxAge: 3600 }))
  mocks.graphql.mockResolvedValueOnce({ account: { username: 'person' } })
  mocks.reauthorize.mockResolvedValueOnce(new Response(null, { status: 302, headers: { location: '/reauth' } }))
  expect(await passkeyAccountAction({ action: 'delete', id: 'key' })).toEqual({ redirect: '/reauth' })
  expect(mocks.reauthorize).toHaveBeenCalledWith('/account/security?confirm=passkeys', 'account', { loginHint: 'person', acrValues: 'aal2', maxAge: 3600 })
})

it('returns an actionable passkey-limit message from either registration phase', async () => {
  for (const action of ['begin', 'finish'] as const) {
    mocks.graphql.mockRejectedValueOnce(new GraphqlRequestError([{ message: 'limit reached', extensions: { code: 11019 } }]))
    expect(await passkeyAccountAction({ action })).toEqual({ error: 'Limit of 5 passkeys reached, delete one to add another' })
  }
  expect(mocks.reauthorize).not.toHaveBeenCalled()
})

it('prepares account-bound recovery codes before a passkey ceremony', async () => {
  const enrollment = { recoveryCodes: ['ABCD-EFGH'], enrollmentToken: 'protected-batch' }
  mocks.graphql.mockResolvedValueOnce({ prepareMfaRecoveryCodes: enrollment })
  expect(await passkeyAccountAction({ action: 'prepare' })).toEqual({ recoveryEnrollment: enrollment })
  expect(mocks.graphql).toHaveBeenCalledWith('mutation PrepareMfaRecoveryCodes { prepareMfaRecoveryCodes { recoveryCodes enrollmentToken } }', undefined, { authorization: 'elevated' })
})

it('forwards the protected recovery batch into passkey registration', async () => {
  mocks.graphql.mockResolvedValueOnce({ beginPasskeyRegistration: {} })
  await passkeyAccountAction({ action: 'begin', recoveryEnrollmentToken: 'protected-batch' })
  expect(mocks.graphql.mock.calls[0][1]).toEqual({ recoveryEnrollmentToken: 'protected-batch' })
})

it.each(['prepare', 'begin', 'finish', 'delete'] as const)('uses ordinary sign-in when the %s passkey request loses its session', async (action) => {
  mocks.graphql.mockResolvedValueOnce(undefined)
  expect(await passkeyAccountAction({ action })).toEqual({ redirect: 'https://identity.example.com/oauth2/authorize?state=signin' })
  expect(mocks.reauthorize).not.toHaveBeenCalled()
  expect(mocks.restart).toHaveBeenCalledWith('/account/security?confirm=passkeys')
})

it('returns localized fallback on malformed credential JSON or generic errors without leaking message', async () => {
  expect(await passkeyAccountAction({ action: 'finish', id: 'c', name: 'Lap', credential: '{bad-json' })).toEqual({
    error: 'Unable to verify the passkey, try again or use another sign-in method',
  })
  mocks.graphql.mockRejectedValueOnce(new Error('internal ECONNREFUSED detail'))
  const result = await passkeyAccountAction({ action: 'begin' })
  expect(result).toEqual({
    error: 'Unable to verify the passkey, try again or use another sign-in method',
  })
})
