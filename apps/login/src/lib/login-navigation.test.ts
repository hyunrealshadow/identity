import { describe, expect, it } from 'vitest'

import { loginChallengeDestination } from './login-navigation'

describe('login navigation', () => {
  it('builds a same-origin challenge path without an internal request origin', () => {
    expect(
      loginChallengeDestination('protected-login', 'password', 'zh-CN'),
    ).toBe(
      '/login/challenge?login_id=protected-login&credential_type=password&ui_locales=zh-CN',
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
      '/login/challenge?login_id=protected-login&credential_type=otp&ui_locales=zh-CN&restart=required',
    )
  })
})
