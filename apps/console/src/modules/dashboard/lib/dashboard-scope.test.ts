// @vitest-environment node
import { expect, it } from 'vitest'
import { dashboardScope } from './dashboard-scope'

it('selects authorized overview fields without reviving historical grants', () => {
  const scope = dashboardScope({
    effectiveScopes: ['management.session.read'],
    requestableScopes: ['management.user.read'],
    grantedScopes: ['management.client.read', 'management.resource.read'],
    authentication: { acr: 'aal1', authTime: null, aal2: false, recent: false },
  })
  expect(scope).toEqual({
    users: true,
    sessions: true,
    clients: false,
    resources: false,
    hasAny: true,
  })
  expect(dashboardScope(null).hasAny).toBe(false)
})
