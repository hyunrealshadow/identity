import { beforeEach, expect, it, vi } from 'vitest'
import { identityJson, IdentityApiError } from './identity.server'
import { submitPasswordChange } from './password-change.server'

vi.mock('./identity.server', async (original) => ({
  ...await original<typeof import('./identity.server')>(),
  identityJson: vi.fn(),
}))
beforeEach(() => { vi.mocked(identityJson).mockReset() })

function submit(values: Record<string, string>) {
  return submitPasswordChange(new Request('https://login.example.com/login/change-password', {
    method: 'POST',
    body: new URLSearchParams({ login_id: 'login', csrf_token: 'csrf', ui_locales: 'zh-CN', ...values }),
  }))
}

function flash(response: Response) {
  const cookie = response.headers.get('set-cookie') ?? ''
  return JSON.parse(decodeURIComponent(cookie.slice(cookie.indexOf('=') + 1, cookie.indexOf(';')))) as {
    fields?: Record<string, string>
  }
}

it('continues the sign-in after the new password is set', async () => {
  vi.mocked(identityJson).mockResolvedValue({ status: 'authenticated', continue_uri: '/oauth2/continue?login_id=login' })
  const response = await submit({ new_password: 'new-password', confirm_password: 'new-password' })
  expect(identityJson).toHaveBeenCalledWith('/api/auth/login/password-change', expect.objectContaining({
    csrfToken: 'csrf',
    body: { id: 'login', new_password: 'new-password' },
  }))
  expect(response.headers.get('location')).toBe('/oauth2/continue?login_id=login&ui_locales=zh-CN')
})

it('refuses mismatched passwords before calling the identity API', async () => {
  const response = await submit({ new_password: 'one', confirm_password: 'two' })
  expect(identityJson).not.toHaveBeenCalled()
  expect(response.headers.get('location')).toBe('/login/change-password?login_id=login&ui_locales=zh-CN')
  expect(flash(response).fields).toEqual({ confirm_password: '两次输入的新密码不一致' })
})

it('shows a reused password on its field', async () => {
  vi.mocked(identityJson).mockRejectedValue(
    new IdentityApiError('Invalid', 400, 10002, [{ field: 'newPassword', message: '不能使用最近用过的 3 个密码，请换一个', code: 11034 }]),
  )
  const response = await submit({ new_password: 'old-password', confirm_password: 'old-password' })
  expect(flash(response).fields).toEqual({ new_password: '不能使用最近用过的 3 个密码，请换一个' })
})

it('asks to restart an expired login', async () => {
  vi.mocked(identityJson).mockRejectedValue(new IdentityApiError('Expired', 410, 11004))
  const response = await submit({ new_password: 'new-password', confirm_password: 'new-password' })
  expect(response.headers.get('location')).toBe('/login/change-password?login_id=login&ui_locales=zh-CN&restart=required')
})
