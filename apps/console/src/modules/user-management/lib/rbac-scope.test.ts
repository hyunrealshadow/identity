// @vitest-environment node
import { schemaMetadata } from '@identity/graphql-access'
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

it('derives every affordance from a field that the schema still declares', () => {
  const declared = Object.values(schemaMetadata.types).flatMap((type) =>
    Object.values(type?.fields ?? {}).flatMap((field) =>
      (field?.policies ?? []).flatMap((policy) => policy.scopes),
    ),
  )
  const scope = rbacScope({ ...snapshot, requestableScopes: [...new Set(declared)] })
  for (const [name, allowed] of Object.entries(scope)) {
    expect(allowed, name).toBe(true)
  }
})
