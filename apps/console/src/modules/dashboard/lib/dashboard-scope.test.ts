// @vitest-environment node
import { describe, expect, it } from 'vitest'

import {
  DASHBOARD_READ_SCOPES,
  dashboardScope,
} from '#/modules/dashboard/lib/dashboard-scope'
import type { EffectivePermissions } from '#/lib/workspace'

function permissions(
  overrides: Partial<EffectivePermissions> = {},
): EffectivePermissions {
  return {
    role: null,
    requestableScopes: [],
    grantedScopes: [],
    effectiveScopes: [],
    authentication: {
      acr: 'urn:identity:aal2',
      authTime: '2026-10-22T12:00:00Z',
      aal2: true,
      recent: true,
    },
    ...overrides,
  }
}

describe('dashboard scope selection', () => {
  it('selects only modules with an effective read scope', () => {
    const scope = dashboardScope(
      permissions({
        effectiveScopes: [
          DASHBOARD_READ_SCOPES.users,
          DASHBOARD_READ_SCOPES.sessions,
        ],
      }),
    )

    expect(scope).toMatchObject({
      users: true,
      applications: false,
      sessions: true,
      resources: false,
      hasAny: true,
      stepUp: false,
    })
  })

  it('requests step-up for an AAL1 principal with requestable read scopes', () => {
    const scope = dashboardScope(
      permissions({
        authentication: {
          acr: 'urn:identity:aal1',
          authTime: '2026-10-22T12:00:00Z',
          aal2: false,
          recent: true,
        },
        requestableScopes: [DASHBOARD_READ_SCOPES.users],
      }),
    )

    expect(scope.hasAny).toBe(false)
    expect(scope.stepUp).toBe(true)
  })

  it('does not show step-up when authentication strength is not the blocker', () => {
    const scope = dashboardScope(
      permissions({
        requestableScopes: [DASHBOARD_READ_SCOPES.users],
      }),
    )

    expect(scope.hasAny).toBe(false)
    expect(scope.stepUp).toBe(false)
  })

  it('does not show step-up for a principal without management permissions', () => {
    const scope = dashboardScope(
      permissions({
        role: null,
        authentication: {
          acr: 'urn:identity:aal1',
          authTime: '2026-10-22T12:00:00Z',
          aal2: false,
          recent: true,
        },
        requestableScopes: [],
      }),
    )

    expect(scope.hasAny).toBe(false)
    expect(scope.stepUp).toBe(false)
  })

  it('skips every module when bootstrap has no permissions', () => {
    expect(dashboardScope(null)).toMatchObject({
      users: false,
      applications: false,
      sessions: false,
      resources: false,
      hasAny: false,
      stepUp: false,
    })
  })
})
