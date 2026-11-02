// @vitest-environment node
import { expect, it } from 'vitest'
import type { EffectivePermissions } from '#/lib/workspace'
import { rbacScope } from './rbac-scope'

const snapshot: EffectivePermissions = {
  role: null,
  effectiveScopes: [],
  requestableScopes: [],
  grantedScopes: [],
  authentication: { acr: 'aal1', authTime: null, aal2: false, recent: false },
}

it('does not offer capabilities from withdrawn historical grants', () => {
  const scope = rbacScope({
    ...snapshot,
    grantedScopes: [
      'management.role.write',
      'management.group_membership.write',
    ],
  })
  expect(scope.rolesWrite).toBe(false)
  expect(scope.groupMembershipsWrite).toBe(false)
})

it('offers requestable actions without imposing a second authentication policy', () => {
  const scope = rbacScope({
    ...snapshot,
    requestableScopes: [
      'management.role.write',
      'management.group_membership.write',
    ],
  })
  expect(scope.rolesWrite).toBe(true)
  expect(scope.rolesRead).toBe(false)
  expect(scope.assignmentsWrite).toBe(false)
  expect(scope.groupMembershipsWrite).toBe(true)
})
