import { describe, expect, it } from 'vitest'
import { readFileSync } from 'node:fs'
import { buildSchema, parse, validate } from 'graphql'
import { preflightOperation as evaluateOperation } from './preflight'

const schema = buildSchema(readFileSync(new URL('../../../graphql/schema.graphql', import.meta.url), 'utf8'))

function preflightOperation(...args: Parameters<typeof evaluateOperation>) {
  expect(validate(schema, parse(args[0]))).toEqual([])
  return evaluateOperation(...args)
}

const now = 1_800_000_000
const user = { user: true, acr: 'aal2', authTime: now, now }

describe('executable schema access contract', () => {
  it('prechecks a real management write before submission', () => {
    const decision = preflightOperation('mutation { createGroup(input: {name: "Readers", names: [{locale: "en-US", value: "Readers"}]}) { groupId } }', {}, {
      ...user, scopes: ['management.group.write'], authTime: now - 301,
    })
    expect(decision).toMatchObject({ status: 'reauthentication', acrValues: 'aal2', maxAge: 300 })
  })

  it('includes guarded payload fields as well as the mutation itself', () => {
    const decision = preflightOperation('mutation { createUser(input: {username: "reader", email: "reader@example.test", password: "Example test password"}) { user { id version } } }', {}, {
      ...user, scopes: ['management.user.create'],
    })
    expect(decision.status).toBe('forbidden')
    expect(decision.requiredScopes).toContain('management.user.read')
  })

  it('uses real operation variables for optional overview fields', () => {
    const query = 'query Overview($users: Boolean!) { instanceOverview { users @include(if: $users) { total } generatedAt } }'
    expect(preflightOperation(query, { users: false }, { ...user, scopes: [] }).status).toBe('allowed')
    expect(preflightOperation(query, { users: true }, { ...user, scopes: [] }).status).toBe('forbidden')
  })

  it('publishes and evaluates the account-dependent elevated time window', () => {
    const query = 'mutation { prepareMfaManagement }'
    expect(preflightOperation(query, {}, { ...user, scopes: ['account.update'], authTime: now - 1000, mfaEnabled: true }).status).toBe('allowed')
    expect(preflightOperation(query, {}, { ...user, scopes: ['account.update'], authTime: now - 1000, mfaEnabled: false })).toMatchObject({ status: 'reauthentication', maxAge: 300 })
  })

  it('does not accept an unrelated ACR merely containing an aal2 substring', () => {
    expect(preflightOperation('query { users { edges { node { id } } } }', {}, {
      ...user, acr: 'not-aal2', scopes: ['management.user.read'],
    }).status).toBe('reauthentication')
  })

  it('keeps human assurance requirements separate from allowed machine grants', () => {
    expect(preflightOperation('query { users { edges { node { id } } } }', {}, {
      user: false, scopes: ['management.user.read'], now,
    }).status).toBe('allowed')
    expect(preflightOperation('query { account { id } }', {}, {
      user: false, scopes: ['account.read'], now,
    }).status).toBe('forbidden')
  })

  it('does not infer a longer ordinary window from unknown factor state', () => {
    expect(preflightOperation('mutation { prepareMfaManagement }', {}, {
      ...user, scopes: ['account.update'], authTime: now - 1000,
    }).status).toBe('unknown')
    expect(preflightOperation('mutation { updateUsername(input: {username: "reader"}) { user { id } } }', {}, {
      scopes: ['account.update'], user: true, authTime: now, now,
    }).status).toBe('reauthentication')
  })

  it('keeps the ordinary MFA preference change free of freshness requirements', () => {
    expect(preflightOperation('mutation { updatePreferredMfaMethod(method: PASSKEY) }', {}, {
      ...user, acr: 'aal1', authTime: now - 10000, scopes: ['account.update'],
    }).status).toBe('allowed')
  })
})
