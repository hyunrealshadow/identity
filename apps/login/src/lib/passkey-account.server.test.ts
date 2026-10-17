import { beforeEach, expect, it, vi } from 'vitest'

const mocks = vi.hoisted(() => ({ graphql: vi.fn(), reauthorize: vi.fn(), origin: vi.fn() }))
vi.mock('@tanstack/react-start/server', () => ({ getRequestHeader: mocks.origin }))
vi.mock('./graphql.server', async (original) => ({ ...await original<typeof import('./graphql.server')>(), identityGraphql: mocks.graphql }))
vi.mock('./oauth.server', () => ({ startReauthorization: mocks.reauthorize }))
vi.mock('./runtime-config.server', () => ({ loadApplicationUrl: () => 'https://login.example.com' }))
vi.mock('./i18n.server', () => ({ requestLocale: () => 'en-US' }))

import { GraphqlRequestError } from './graphql.server'
import { passkeyAccountAction } from './passkey-account.server'

beforeEach(() => {
  vi.clearAllMocks()
  mocks.origin.mockReturnValue('https://login.example.com')
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
  expect(mocks.graphql).toHaveBeenCalledWith('mutation { beginPasskeyRegistration }', undefined, { authorization: 'elevated' })
})

it('passes the credential JSON to the authenticated completion mutation', async () => {
  mocks.graphql.mockResolvedValueOnce({ finishPasskeyRegistration: true })
  expect(await passkeyAccountAction({ action: 'finish', id: 'challenge', name: 'Laptop', credential: '{"id":"credential"}' })).toEqual({ ok: true })
  expect(mocks.graphql.mock.calls[0][1]).toEqual({ id: 'challenge', name: 'Laptop', credential: { id: 'credential' } })
})

it('binds reauthentication to the current account and honors AAL2', async () => {
  mocks.graphql.mockRejectedValueOnce(new GraphqlRequestError([{ message: 'step up', extensions: { code: 'insufficient_user_authentication' } }], { acrValues: 'aal2', maxAge: 3600 }))
  mocks.graphql.mockResolvedValueOnce({ viewer: { account: { username: 'person' } } })
  mocks.reauthorize.mockResolvedValueOnce(new Response(null, { status: 302, headers: { location: '/reauth' } }))
  expect(await passkeyAccountAction({ action: 'delete', id: 'key' })).toEqual({ redirect: '/reauth' })
  expect(mocks.reauthorize).toHaveBeenCalledWith('/account/security', 'account', { loginHint: 'person', acrValues: 'aal2', maxAge: 3600 })
})

it('returns an actionable passkey-limit message from either registration phase', async () => {
  for (const action of ['begin', 'finish'] as const) {
    mocks.graphql.mockRejectedValueOnce(new GraphqlRequestError([{ message: 'limit reached', extensions: { code: 11019 } }]))
    expect(await passkeyAccountAction({ action })).toEqual({ error: 'You can add up to 5 passkeys. Delete a passkey before adding another.' })
  }
  expect(mocks.reauthorize).not.toHaveBeenCalled()
})
