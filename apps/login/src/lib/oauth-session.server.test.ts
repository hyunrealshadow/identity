import { describe, expect, it } from 'vitest'

import { deriveSessionPassword } from './oauth-session.server'

describe('encrypted login cookie password derivation', () => {
  it('is stable and long enough for TanStack Start sessions', () => {
    const password = deriveSessionPassword('session-secret', 'authorization')

    expect(password).toHaveLength(64)
    expect(password).toBe(
      deriveSessionPassword('session-secret', 'authorization'),
    )
  })

  it('separates authorization and OAuth flow cookies', () => {
    expect(deriveSessionPassword('session-secret', 'authorization')).not.toBe(
      deriveSessionPassword('session-secret', 'oauth-flow'),
    )
  })

  it('changes only when the independent session secret rotates', () => {
    expect(deriveSessionPassword('first-session-secret', 'authorization')).not.toBe(
      deriveSessionPassword('second-session-secret', 'authorization'),
    )
  })
})
