import { describe, expect, it } from 'vitest'

import { ConfigError, validateRuntimeConfig } from '#/lib/config'

const origin = window.location.origin

function baseConfig() {
  return {
    issuer: 'https://identity.example.test',
    graphqlUrl: 'https://identity.example.test/graphql',
    clientId: 'console-client',
    redirectUri: `${origin}/callback`,
    postLogoutRedirectUri: `${origin}/signed-out`,
    accountUrl: 'https://login.example.test/account',
    scope: 'openid profile email',
    displayName: 'Identity Console',
    environment: 'test',
  }
}

function configError(value: unknown): string | undefined {
  try {
    validateRuntimeConfig(value)
    return undefined
  } catch (error) {
    return error instanceof ConfigError ? error.code : 'unexpected_error'
  }
}

describe('console runtime configuration', () => {
  it('accepts wildcard selectors at arbitrary prefix depth and rejects malformed ones', () => {
    expect(validateRuntimeConfig({ ...baseConfig(), scope: 'openid management.user.profile.* account.* session.*' }).scope).toBe('openid management.user.profile.* account.* session.*')
    expect(configError({ ...baseConfig(), scope: 'openid management.*.read' })).toBe('config_invalid_scope')
  })
  it('accepts a separate account center URL without credentials, query, or fragment', () => {
    const config = validateRuntimeConfig(baseConfig())
    expect(config.accountUrl).toBe('https://login.example.test/account')
  })

  it('requires the account center URL', () => {
    const withoutAccountUrl: Record<string, unknown> = { ...baseConfig() }
    delete withoutAccountUrl.accountUrl
    expect(configError(withoutAccountUrl)).toBe('config_missing_keys')
  })

  it('rejects an account center URL on the Console origin', () => {
    expect(configError({ ...baseConfig(), accountUrl: `${origin}/account` })).toBe(
      'config_invalid_account_url',
    )
  })

  it('allows a same-origin account center outside the Console prefix', () => {
    const value = { ...baseConfig(), redirectUri: `${origin}/console/callback`,
      postLogoutRedirectUri: `${origin}/console/signed-out`, accountUrl: `${origin}/account` }
    expect(validateRuntimeConfig(value).accountUrl).toBe(`${origin}/account`)
    expect(configError({ ...value, accountUrl: `${origin}/console/account` })).toBe('config_invalid_account_url')
  })

  it.each([
    ['credentials', 'https://user:secret@login.example.test/account'],
    ['a query string', 'https://login.example.test/account?returnTo=%2F'],
    ['a fragment', 'https://login.example.test/account#security'],
    ['a non-http scheme', 'javascript:alert(1)'],
  ])('rejects %s as the account center URL', (_label, accountUrl) => {
    const code = configError({ ...baseConfig(), accountUrl })
    expect(code).toBe('config_invalid_url')
  })
})
