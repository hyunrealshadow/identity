// @vitest-environment node
import { describe, expect, it } from 'vitest'

import {
  isCurrentUser,
  userManagementScope,
} from '#/modules/user-management/users/lib/user-scope'
import type { EffectivePermissions } from '#/lib/workspace'

function permissions(
  effectiveScopes: string[],
  requestableScopes: string[] = [],
  aal2 = true,
): EffectivePermissions {
  return {
    role: null,
    requestableScopes,
    grantedScopes: [],
    effectiveScopes,
    authentication: {
      acr: aal2 ? 'urn:identity:aal2' : 'urn:identity:aal1',
      authTime: null,
      aal2,
      recent: true,
    },
  }
}

describe('user management scope', () => {
  it('does not treat revoked historical grants as recoverable authentication', () => {
    const scope = userManagementScope({
      ...permissions([], [], false),
      grantedScopes: ['management.user.read', 'management.user.update'],
    })
    expect(scope.readStepUp).toBe(false)
    expect(scope.writeStepUp).toBe(false)
  })
  it('models write-only access without inventing read permission', () => {
    const scope = userManagementScope(
      permissions(['management.user.create', 'management.user.state']),
    )

    expect(scope.read).toBe(false)
    expect(scope.create).toBe(true)
    expect(scope.state).toBe(true)
    expect(scope.canWrite).toBe(true)
    expect(scope.hasAny).toBe(true)
  })

  it('offers a read step-up only when a user read scope is requestable', () => {
    const scoped = userManagementScope(
      permissions([], ['management.user.read'], false),
    )
    expect(scoped.readStepUp).toBe(true)

    const unrelated = userManagementScope(
      permissions([], ['management.client.read'], false),
    )
    expect(unrelated.readStepUp).toBe(false)
  })

  it('matches the current subject only when the global id is unambiguous', () => {
    expect(isCurrentUser('User:subject-1', 'subject-1')).toBe(true)
    expect(isCurrentUser('User:subject-1', 'subject-2')).toBe(false)
    expect(isCurrentUser('User:subject-1', undefined)).toBe(false)
  })
})
