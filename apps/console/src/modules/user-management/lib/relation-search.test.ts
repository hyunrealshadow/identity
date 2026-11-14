// @vitest-environment node
import { describe, expect, it } from 'vitest'

import { normalizeUserPermissionsSearch, normalizeUserRolesSearch } from '#/modules/user-management/authorization/lib/user-authorization-search'
import { normalizeGroupRolesSearch } from '#/modules/user-management/groups/lib/group-relations-search'
import { normalizeRoleUsersSearch } from '#/modules/user-management/roles/lib/role-users-search'

describe('relation tab URL search', () => {
  it('keeps chosen filters and paging, and drops defaults and unknown values', () => {
    expect(
      normalizeUserRolesSearch({
        status: 'revoked',
        source: 'GROUP',
        size: '50',
        after: 'cursor-a',
        before: 'cursor-b',
      }),
    ).toEqual({ status: 'revoked', source: 'GROUP', size: 50, after: 'cursor-a' })

    // "Active" is the default view of a user's roles, so it is not written.
    expect(
      normalizeUserRolesSearch({ status: 'active', source: 'any', size: '7' }),
    ).toEqual({})
    expect(normalizeRoleUsersSearch({ status: 'everyone' })).toEqual({})
  })

  it('keeps typed search text exactly as entered', () => {
    expect(normalizeGroupRolesSearch({ q: ' admin  ' }).q).toBe(' admin  ')
    expect(normalizeGroupRolesSearch({ q: '' }).q).toBeUndefined()
  })

  it('remembers the chosen API resource of the effective permission list', () => {
    expect(
      normalizeUserPermissionsSearch({ resource: 'resource-id', source: 'DIRECT' }),
    ).toEqual({ resource: 'resource-id', source: 'DIRECT' })
    expect(normalizeUserPermissionsSearch({ resource: '' })).toEqual({})
  })
})
