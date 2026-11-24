import { beforeEach, expect, it, vi } from 'vitest'
import { identityJson, IdentityApiError } from './identity.server'
import { submitPasswordReset } from './password-reset.server'

vi.mock('./identity.server', async (original) => ({
  ...await original<typeof import('./identity.server')>(),
  identityJson: vi.fn(),
}))
beforeEach(() => { vi.mocked(identityJson).mockReset() })

function submit(values: Record<string, string>) {
  return submitPasswordReset(new Request('https://login.example.com/login/reset-password', {
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

it('emails a reset link and shows the sent state', async () => {
  vi.mocked(identityJson).mockResolvedValue({ status: 'sent' })
  const response = await submit({ intent: 'send' })
  expect(identityJson).toHaveBeenCalledWith('/api/auth/login/password-reset', expect.objectContaining({
    csrfToken: 'csrf',
    body: { id: 'login', locales: ['zh-CN'] },
  }))
  expect(response.headers.get('location')).toBe('/login/reset-password?login_id=login&ui_locales=zh-CN')
})

it('returns to the password step after the password is reset', async () => {
  vi.mocked(identityJson).mockResolvedValue({ status: 'password_reset' })
  const response = await submit({ intent: 'reset', token: 'link', new_password: 'new-password', confirm_password: 'new-password' })
  expect(identityJson).toHaveBeenCalledWith('/api/auth/login/password-reset/confirm', expect.objectContaining({
    body: { id: 'login', token: 'link', new_password: 'new-password' },
  }))
  expect(response.headers.get('location')).toBe('/login/password?login_id=login&ui_locales=zh-CN&notice=password_reset')
})

it('refuses mismatched passwords before calling the identity API', async () => {
  const response = await submit({ intent: 'reset', token: 'link', new_password: 'one', confirm_password: 'two' })
  expect(identityJson).not.toHaveBeenCalled()
  expect(response.headers.get('location')).toBe('/login/reset-password?login_id=login&ui_locales=zh-CN&token=link')
  expect(flash(response).fields).toEqual({ confirm_password: '两次输入的新密码不一致' })
})

it('shows a rejected new password on its field and keeps the link', async () => {
  vi.mocked(identityJson).mockRejectedValue(
    new IdentityApiError('Invalid', 400, 10002, [{ field: 'newPassword', message: '密码太短', code: 11013 }]),
  )
  const response = await submit({ intent: 'reset', token: 'link', new_password: 'short', confirm_password: 'short' })
  expect(response.headers.get('location')).toBe('/login/reset-password?login_id=login&ui_locales=zh-CN&token=link')
  expect(flash(response).fields).toEqual({ new_password: '密码太短' })
})

it('asks to restart an expired login', async () => {
  vi.mocked(identityJson).mockRejectedValue(new IdentityApiError('Expired', 410, 11004))
  const response = await submit({ intent: 'send' })
  expect(response.headers.get('location')).toBe('/login/reset-password?login_id=login&ui_locales=zh-CN&restart=required')
})
