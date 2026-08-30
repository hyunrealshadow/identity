import { afterEach, describe, expect, it, vi } from 'vitest'

import {
  callbackUrl,
  exchangeToken,
  OAuthTokenExchangeError,
  reauthenticationRequestParameters,
  reauthenticationScope,
  safeReturnTo,
  tokenAuthenticationIsFresh,
} from './oauth.server'

afterEach(() => {
  delete process.env.IDENTITY_BACKCHANNEL_API_URL
  delete process.env.IDENTITY_BACKCHANNEL_ALLOW_HTTP
  vi.unstubAllGlobals()
})

describe('OAuth reauthentication scopes', () => {
  it('uses the broad account scope assigned to the built-in client', () => {
    expect(reauthenticationScope('account')).toBe('openid account')
    expect(reauthenticationScope('mfa')).toBe('openid account')
  })

  it('keeps password reauthentication scoped to password changes', () => {
    expect(reauthenticationScope('password')).toBe(
      'openid password.change',
    )
  })
})

describe('OAuth reauthentication request', () => {
  it('targets the current account without overriding RFC 9470 with prompt=login', () => {
    expect(
      reauthenticationRequestParameters('account', {
        loginHint: 'alice',
        acrValues: 'urn:identity:acr:aal1',
        maxAge: 300,
      }),
    ).toEqual({
      loginHint: 'alice',
      acrValues: 'urn:identity:acr:aal1',
      maxAge: 300,
    })
  })

  it('uses the purpose defaults when the challenge omits requirements', () => {
    expect(reauthenticationRequestParameters('mfa', {
      loginHint: 'alice',
    })).toEqual({
      loginHint: 'alice',
      acrValues: 'urn:identity:acr:aal2',
      maxAge: 0,
    })
  })
})

describe('local authentication freshness', () => {
  const token = (claims: Record<string, unknown>) =>
    `header.${Buffer.from(JSON.stringify(claims)).toString('base64url')}.signature`

  it('uses the same five-minute recent-authentication window as the API', () => {
    expect(tokenAuthenticationIsFresh(token({ auth_time: 700, acr: 'urn:identity:acr:aal1' }), undefined, 1_000)).toBe(true)
    expect(tokenAuthenticationIsFresh(token({ auth_time: 699, acr: 'urn:identity:acr:aal1' }), undefined, 1_000)).toBe(false)
  })

  it('requires AAL2 and uses its one-hour freshness window', () => {
    const aal2 = 'urn:identity:acr:aal2'
    expect(tokenAuthenticationIsFresh(token({ auth_time: 400, acr: aal2 }), aal2, 4_000)).toBe(true)
    expect(tokenAuthenticationIsFresh(token({ auth_time: 399, acr: aal2 }), aal2, 4_000)).toBe(false)
    expect(tokenAuthenticationIsFresh(token({ auth_time: 4_000, acr: 'urn:identity:acr:aal1' }), aal2, 4_000)).toBe(false)
  })
})

describe('OAuth return locations', () => {
  it('uses the top-level frontend callback route', () => {
    expect(callbackUrl('https://identity.example/')).toBe(
      'https://identity.example/callback',
    )
  })

  it('preserves same-origin paths including query and fragment', () => {
    expect(safeReturnTo('/account/security?step=mfa#verify', '/account')).toBe(
      '/account/security?step=mfa#verify',
    )
  })

  it('rejects absolute and protocol-relative redirects', () => {
    expect(safeReturnTo('https://attacker.example', '/account')).toBe('/account')
    expect(safeReturnTo('//attacker.example/path', '/account')).toBe('/account')
  })

  it('uses the fallback for missing or invalid values', () => {
    expect(safeReturnTo(undefined, '/account')).toBe('/account')
    expect(safeReturnTo('account/security', '/account')).toBe('/account')
  })
})

describe('OAuth token exchange', () => {
  it('coalesces concurrent exchanges of the same one-time grant', async () => {
    process.env.IDENTITY_BACKCHANNEL_API_URL = 'http://identity-server:5150'
    process.env.IDENTITY_BACKCHANNEL_ALLOW_HTTP = 'true'
    let resolveFetch!: (response: Response) => void
    const response = new Promise<Response>((resolve) => {
      resolveFetch = resolve
    })
    const fetchMock = vi.fn(() => response)
    vi.stubGlobal('fetch', fetchMock)
    const body = new URLSearchParams({
      grant_type: 'refresh_token',
      refresh_token: 'one-time-token',
    })

    const first = exchangeToken(body, 'client', 'secret')
    const second = exchangeToken(body, 'client', 'secret')
    resolveFetch(
      Response.json({ access_token: 'access', expires_in: 3600 }),
    )

    await expect(Promise.all([first, second])).resolves.toEqual([
      { access_token: 'access', expires_in: 3600 },
      { access_token: 'access', expires_in: 3600 },
    ])
    expect(fetchMock).toHaveBeenCalledTimes(1)
    expect(fetchMock.mock.calls[0]?.[0]).toEqual(
      new URL('http://identity-server:5150/oauth2/token'),
    )
  })

  it('includes and trims the RFC 6749 error description', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn(async () =>
        Response.json(
          {
            error: 'invalid_grant ',
            error_description: 'Authorization code has already been used. ',
          },
          { status: 400 },
        ),
      ),
    )

    const exchange = exchangeToken(
      new URLSearchParams({
        grant_type: 'authorization_code',
        code: 'used-code',
      }),
      'client',
      'secret',
    )

    await expect(exchange).rejects.toThrow(
      'OAuth authorization_code exchange failed: invalid_grant: Authorization code has already been used.',
    )
    await expect(exchange).rejects.toMatchObject({
      name: 'OAuthTokenExchangeError',
      grantType: 'authorization_code',
      oauthError: 'invalid_grant',
      status: 400,
    } satisfies Partial<OAuthTokenExchangeError>)
  })
})
