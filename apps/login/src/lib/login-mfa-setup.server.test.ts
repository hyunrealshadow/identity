import { beforeEach, expect, it, vi } from 'vitest'
import { identityJson, IdentityApiError } from './identity.server'
import { submitLoginMfaSetup } from './login-mfa-setup.server'

vi.mock('./identity.server', async (original) => ({
  ...await original<typeof import('./identity.server')>(),
  identityJson: vi.fn(),
}))
beforeEach(() => { vi.mocked(identityJson).mockReset() })

function submit(values: Record<string, string>) {
  return submitLoginMfaSetup(new Request('https://login.example.com/login/mfa-setup', {
    method: 'POST',
    body: new URLSearchParams({ login_id: 'login', csrf_token: 'csrf', ui_locales: 'zh-CN', ...values }),
  }))
}

function flash(response: Response) {
  const cookie = response.headers.get('set-cookie') ?? ''
  return JSON.parse(decodeURIComponent(cookie.slice(cookie.indexOf('=') + 1, cookie.indexOf(';')))) as {
    message: string
    fields?: Record<string, string>
  }
}

it('continues the authorization after the new authenticator is confirmed', async () => {
  vi.mocked(identityJson).mockResolvedValue({ status: 'authenticated', continue_uri: '/oauth2/continue' })
  const response = await submit({ code: '123456' })
  expect(identityJson).toHaveBeenCalledWith('/api/auth/login/mfa-enrollment/confirm', expect.objectContaining({
    body: { id: 'login', code: '123456' },
  }))
  expect(response.headers.get('location')).toBe('/oauth2/continue?ui_locales=zh-CN')
})

it('returns a rejected code to the code field of the same setup', async () => {
  vi.mocked(identityJson).mockRejectedValue(new IdentityApiError('Invalid code', 401, 11002, [
    { field: 'code', code: 11002, message: '验证码错误' },
  ]))
  const response = await submit({ code: '000000', recovery_saved: '2026-11-13T10:00:00Z' })
  // The retry returns to code entry, past the recovery codes already saved.
  expect(response.headers.get('location')).toBe(
    '/login/mfa-setup?login_id=login&ui_locales=zh-CN&recovery_saved=2026-11-13T10%3A00%3A00Z&step=verify',
  )
  expect(flash(response).fields).toEqual({ code: '验证码错误' })
})

it('asks for a code before calling the identity API', async () => {
  const response = await submit({ code: '' })
  expect(identityJson).not.toHaveBeenCalled()
  expect(response.headers.get('location')).toBe('/login/mfa-setup?login_id=login&ui_locales=zh-CN&step=verify')
})

it('switches the pending setup to the legacy algorithm without confirming it', async () => {
  vi.mocked(identityJson).mockResolvedValue({})
  const response = await submit({ intent: 'legacy', code: '123456' })
  expect(identityJson).toHaveBeenCalledWith('/api/auth/login/mfa-enrollment/algorithm', expect.objectContaining({
    body: { id: 'login', algorithm: 'SHA1' },
  }))
  expect(identityJson).toHaveBeenCalledTimes(1)
  expect(response.headers.get('location')).toBe('/login/mfa-setup?login_id=login&ui_locales=zh-CN&step=verify')
})

it('offers a restart when the sign-in expired during setup', async () => {
  vi.mocked(identityJson).mockRejectedValue(new IdentityApiError('Expired', 400, 11004))
  const response = await submit({ code: '123456' })
  expect(response.headers.get('location')).toBe('/login/mfa-setup?login_id=login&ui_locales=zh-CN&restart=required')
})
