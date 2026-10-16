import { describe, expect, it } from 'vitest'

import { loginChallengeDestination, loginCredentialType, loginMethodPath } from './login-navigation'

describe('login navigation', () => {
  it.each([
    ['password', 'password'],
    ['passkey', 'passkey'],
    ['otp', 'otp'],
    ['recovery-code', 'recovery_code'],
  ])('maps the %s path to the backend credential type', (method, credentialType) => {
    expect(loginCredentialType(method)).toBe(credentialType)
    expect(loginMethodPath(credentialType)).toBe(`/login/${method}`)
    expect(loginChallengeDestination('rp+login/id', credentialType)).toBe(
      `/login/${method}?login_id=rp%2Blogin%2Fid`,
    )
  })

  it.each(['challenge', 'unknown', '__proto__', 'constructor'])('rejects unknown method %s', (method) => {
    expect(loginCredentialType(method)).toBeUndefined()
    expect(() => loginMethodPath(method)).toThrow('Unsupported login method')
  })

  it('builds a same-origin challenge path without an internal request origin', () => {
    expect(
      loginChallengeDestination('protected-login', 'password', 'zh-CN'),
    ).toBe(
      '/login/password?login_id=protected-login&ui_locales=zh-CN',
    )
  })

  it('marks a challenge that requires an explicit restart', () => {
    expect(
      loginChallengeDestination(
        'protected-login',
        'otp',
        'zh-CN',
        'required',
      ),
    ).toBe(
      '/login/otp?login_id=protected-login&ui_locales=zh-CN&restart=required',
    )
  })
})
