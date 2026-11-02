// @vitest-environment node
import { describe, expect, it } from 'vitest'
import { scopeMatches, validScopeSelector } from './scope-pattern'

describe('scope selectors', () => {
  it('matches descendants at any prefix depth without crossing boundaries', () => {
    expect(scopeMatches('management.*', 'management.user.read')).toBe(true)
    expect(scopeMatches('management.user.*', 'management.user.profile.read')).toBe(true)
    expect(scopeMatches('account.*', 'account.update')).toBe(true)
    expect(scopeMatches('session.*', 'session.revoke')).toBe(true)
    expect(scopeMatches('management.user.*', 'management.user2.read')).toBe(false)
    expect(scopeMatches('management.*', 'management')).toBe(false)
    expect(scopeMatches('account', 'account.read')).toBe(false)
    expect(scopeMatches('account.update', 'account.read')).toBe(false)
  })
  it('rejects malformed or embedded wildcard selectors', () => {
    for (const value of ['*', 'management*', 'management.*.read', 'management..*', '.management.*']) {
      expect(validScopeSelector(value)).toBe(false)
    }
    expect(validScopeSelector('management.user.profile.*')).toBe(true)
  })
})
