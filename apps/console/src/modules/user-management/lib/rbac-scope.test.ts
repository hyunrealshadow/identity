// @vitest-environment node
import { describe, expect, it } from 'vitest'

import type { EffectivePermissions } from '#/lib/workspace'
import {
  RBAC_SCOPES,
  rbacScope,
} from '#/modules/user-management/lib/rbac-scope'

function permissions(
  scopes: string[],
  options: {
    aal2?: boolean
    recent?: boolean
    requestable?: string[]
  } = {},
): EffectivePermissions {
  return {
    role: null,
    effectiveScopes: scopes,
    grantedScopes: scopes,
    requestableScopes: options.requestable ?? scopes,
    authentication: {
      acr: options.aal2 ? 'urn:identity:aal2' : 'urn:identity:aal1',
      authTime: null,
      aal2: options.aal2 ?? false,
      recent: options.recent ?? false,
    },
  }
}

describe('RBAC console scopes', () => {
  it('does not reauthenticate for a historical grant that is no longer requestable', () => {
    const scope = rbacScope({
      ...permissions([], { requestable: [], aal2: false }),
      grantedScopes: [RBAC_SCOPES.rolesRead, RBAC_SCOPES.rolesWrite],
    })
    expect(scope.roleReadStepUp).toBe(false)
    expect(scope.roleWriteStepUp).toBe(false)
  })
  it('offers group reauthentication without an administrator role label', () => {
    const scope = rbacScope(permissions([RBAC_SCOPES.groupsRead], {
      aal2: true,
      recent: false,
      requestable: [RBAC_SCOPES.groupsRead, RBAC_SCOPES.groupsWrite],
    }))
    expect(scope.groupsWrite).toBe(false)
    expect(scope.groupsWriteReady).toBe(false)
    expect(scope.groupsWriteStepUp).toBe(true)
  })
  it('does not require a read scope to open a write-only role form', () => {
    const scope = rbacScope(
      permissions([RBAC_SCOPES.rolesWrite], {
        aal2: true,
        recent: true,
      }),
    )
    expect(scope.rolesRead).toBe(false)
    expect(scope.rolesWrite).toBe(true)
    expect(scope.roleWriteReady).toBe(true)
    expect(scope.roleWriteStepUp).toBe(false)
  })

  it('requires recent strong authentication for role writes', () => {
    const stale = rbacScope(
      permissions([RBAC_SCOPES.rolesRead, RBAC_SCOPES.rolesWrite], {
        aal2: true,
        recent: false,
      }),
    )
    expect(stale.rolesRead).toBe(true)
    expect(stale.roleWriteReady).toBe(false)
    expect(stale.roleWriteStepUp).toBe(true)
  })

  it('offers step-up only when a write scope is requestable', () => {
    const withoutRequest = rbacScope(
      permissions([RBAC_SCOPES.rolesRead]),
    )
    expect(withoutRequest.roleWriteStepUp).toBe(false)

    const requestable = rbacScope(
      permissions([RBAC_SCOPES.rolesRead], {
        requestable: [RBAC_SCOPES.rolesRead, RBAC_SCOPES.rolesWrite],
      }),
    )
    expect(requestable.roleWriteStepUp).toBe(true)
  })

  it('requires recent strong authentication for permission writes', () => {
    const stale = rbacScope(
      permissions(
        [RBAC_SCOPES.permissionRead, RBAC_SCOPES.permissionWrite],
        { aal2: true, recent: false, requestable: [RBAC_SCOPES.permissionWrite] },
      ),
    )
    expect(stale.permissionRead).toBe(true)
    expect(stale.permissionReadStepUp).toBe(false)
    expect(stale.permissionWriteReady).toBe(false)
    expect(stale.permissionWriteStepUp).toBe(true)

    const ready = rbacScope(
      permissions(
        [RBAC_SCOPES.permissionRead, RBAC_SCOPES.permissionWrite],
        { aal2: true, recent: true },
      ),
    )
    expect(ready.permissionWriteReady).toBe(true)
    expect(ready.permissionWriteStepUp).toBe(false)
  })

  it('offers permission read step-up only when the read scope is requestable', () => {
    const withoutRequest = rbacScope(permissions([]))
    expect(withoutRequest.permissionReadStepUp).toBe(false)

    const requestable = rbacScope(
      permissions([], { requestable: [RBAC_SCOPES.permissionRead] }),
    )
    expect(requestable.permissionReadStepUp).toBe(true)
  })

  it('keeps assignment writes separate from role directory writes', () => {
    const scope = rbacScope(
      permissions([RBAC_SCOPES.rolesWrite], {
        aal2: true,
        recent: true,
      }),
    )
    expect(scope.roleWriteReady).toBe(true)
    expect(scope.assignmentWriteReady).toBe(false)
    const assignment = rbacScope(permissions([RBAC_SCOPES.assignmentsWrite], { aal2: true, recent: true }))
    expect(assignment.assignmentWriteReady).toBe(true)
    expect(assignment.roleWriteReady).toBe(false)
  })
})
