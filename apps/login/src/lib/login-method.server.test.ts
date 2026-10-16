import { beforeEach, expect, it, vi } from 'vitest'
import { identityJson, IdentityApiError } from './identity.server'
import { submitLoginMethod } from './login-method.server'

vi.mock('./identity.server', async (original) => ({
  ...await original<typeof import('./identity.server')>(),
  identityJson: vi.fn(),
}))
beforeEach(() => { vi.mocked(identityJson).mockReset() })

function submit(method: string, values: Record<string, string>, enhanced = false) {
  return submitLoginMethod(new Request(`https://login.example.com/login/${method}`, {
      method: 'POST',
      body: new URLSearchParams({ login_id: 'login', csrf_token: 'csrf', ui_locales: 'zh-CN', ...values }),
      headers: enhanced ? { 'x-enhanced-form': '1' } : undefined,
    }), method)
}

it('takes the credential type from the route instead of a conflicting form value', async () => {
  vi.mocked(identityJson).mockResolvedValue({ status: 'authenticated', continue_uri: '/oauth2/continue' })
  const response = await submit('otp', { credential_type: 'password', totp: '123456' })
  expect(identityJson).toHaveBeenCalledWith('/api/auth/login/challenge', expect.objectContaining({
    body: { id: 'login', credential_type: 'otp', credential: '123456' },
  }))
  expect(response.headers.get('location')).toBe('/oauth2/continue')
})

it.each([false, true])('preserves the recovery-code path and locale after an invalid credential (enhanced=%s)', async (enhanced) => {
  vi.mocked(identityJson).mockRejectedValue(new IdentityApiError('Invalid code', 401, 11001))
  const response = await submit('recovery-code', { credential: 'bad-code' }, enhanced)
  const destination = enhanced ? (await response.json()).redirect : response.headers.get('location')
  expect(destination).toBe('/login/recovery-code?login_id=login&ui_locales=zh-CN')
  expect(response.headers.get('set-cookie')).toContain('Path=/login/recovery-code;')
})

it('navigates to the preferred MFA path after password verification', async () => {
  vi.mocked(identityJson).mockResolvedValue({ status: 'mfa_required', preferred_credential_type: 'passkey' })
  const response = await submit('password', { credential: 'password' })
  expect(response.headers.get('location')).toBe('/login/passkey?login_id=login&ui_locales=zh-CN')
})

it('keeps the current method when an expired login needs restarting', async () => {
  vi.mocked(identityJson).mockRejectedValue(new IdentityApiError('Expired', 400, 11004))
  const response = await submit('otp', { totp: '123456' })
  expect(response.headers.get('location')).toBe('/login/otp?login_id=login&ui_locales=zh-CN&restart=required')
})

it('rejects an unknown method before calling the identity API', async () => {
  const response = await submit('unknown', { credential: 'password' })
  expect(response.status).toBe(404)
  expect(identityJson).not.toHaveBeenCalled()
})
