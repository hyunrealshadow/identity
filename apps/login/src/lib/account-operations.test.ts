import { describe, expect, it } from 'vitest'
import { preflightAccountAction } from './account-operations'

function access(age: number, mfaEnabled = true) {
  const context = {
    scopes: ['account.read', 'account.update', 'password.change'], user: true,
    acr: 'aal2', authTime: Math.floor(Date.now() / 1000) - age, mfaEnabled,
  }
  return { default: context, elevated: context }
}
describe('browser account preflight from executable schema directives', () => {
  it('allows fresh credentials and ordinary profile changes without an auth window', () => {
    expect(preflightAccountAction('prepare-change-password', access(0)).status).toBe('allowed')
    expect(preflightAccountAction('update-profile', access(4_000)).status).toBe('allowed')
  })
  it('uses the conditional security window instead of the identifier window', () => {
    expect(preflightAccountAction('prepare-change-password', access(400)).status).toBe('allowed')
    expect(preflightAccountAction('prepare-change-password', access(400, false)).status).toBe('reauthentication')
    expect(preflightAccountAction('update-username', access(400)).status).toBe('reauthentication')
    expect(preflightAccountAction('prepare-change-password', access(3_601)).status).toBe('reauthentication')
  })
  it('rejects missing scopes and defers unsupported actions without guessing', () => {
    expect(preflightAccountAction('change-password', { default: { scopes: [] }, elevated: { scopes: [] } }).status).toBe('forbidden')
    expect(preflightAccountAction('unrecognized', access(0)).status).toBe('unknown')
    expect(preflightAccountAction('change-password').status).toBe('unknown')
  })
  it.each(['passkey-prepare', 'passkey-begin', 'passkey-finish', 'passkey-delete'])('prechecks each passkey protocol step: %s', (action) => {
    expect(preflightAccountAction(action, access(0)).status).toBe('allowed')
    expect(preflightAccountAction(action, access(3_601)).status).toBe('reauthentication')
  })
})
