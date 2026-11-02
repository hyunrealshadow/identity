import { afterEach, describe, expect, it } from 'vitest'

import {
  clearAuthSession,
  getAuthSession,
  peekAccessToken,
  setAuthSession,
  type AuthSession,
} from './session'

function session(expiresAt: number): AuthSession {
  return {
    accessToken: 'access-token',
    idToken: 'id-token',
    expiresAt,
    scope: 'openid',
    grantedScopes: ['openid'],
    claims: {
      sub: 'user-a',
      iss: 'https://issuer.example.test',
      aud: 'console',
      exp: Math.floor(expiresAt / 1000),
    },
  }
}

afterEach(() => {
  clearAuthSession()
})

describe('access token peek', () => {
  it('never exposes an expired token to an API request', () => {
    setAuthSession(session(1_000))

    expect(peekAccessToken(1_000)).toBeNull()
    expect(peekAccessToken(1_001)).toBeNull()
    expect(peekAccessToken(999)).toBe('access-token')
    // The expired session remains readable for claims and the workspace.
    expect(getAuthSession()?.claims.sub).toBe('user-a')
  })
})
