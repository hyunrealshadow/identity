// @vitest-environment node
import { expect, it } from 'vitest'
import { isCurrentUser, userManagementScope } from './user-scope'

it('keeps write-only user capabilities separate from reading users', () => {
  const scope = userManagementScope({
    effectiveScopes: [],
    grantedScopes: [],
    requestableScopes: ['management.user.create'],
    authentication: { acr: 'aal1', authTime: null, aal2: false, recent: false },
  })
  expect(scope.create).toBe(true)
  expect(scope.read).toBe(false)
  expect(scope.state).toBe(false)
})

it('matches the current subject only when the global id is unambiguous', () => {
  expect(isCurrentUser('User:subject-1', 'subject-1')).toBe(true)
  expect(isCurrentUser('User:subject-1', 'subject-2')).toBe(false)
  expect(isCurrentUser('User:subject-1', undefined)).toBe(false)
})
