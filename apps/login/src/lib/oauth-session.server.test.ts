import { describe, expect, it } from 'vitest'

import { deriveSessionPassword } from './oauth-session.server'

describe('encrypted OAuth session password derivation', () => {
  it('is stable and long enough for TanStack Start sessions', () => {
    const password = deriveSessionPassword('client-secret', 'authorization')

    expect(password).toHaveLength(64)
    expect(password).toBe(
      deriveSessionPassword('client-secret', 'authorization'),
    )
  })

  it('separates authorization and OAuth flow cookies', () => {
    expect(deriveSessionPassword('client-secret', 'authorization')).not.toBe(
      deriveSessionPassword('client-secret', 'oauth-flow'),
    )
  })

  it('changes when the installed client secret rotates', () => {
    expect(deriveSessionPassword('first-secret', 'authorization')).not.toBe(
      deriveSessionPassword('second-secret', 'authorization'),
    )
  })
})
