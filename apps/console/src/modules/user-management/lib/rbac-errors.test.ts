// @vitest-environment node
import { describe, expect, it } from 'vitest'

import {
  hasFieldErrors,
  rbacConflict,
  rbacFieldErrors,
} from '#/modules/user-management/lib/rbac-errors'

describe('RBAC error presentation', () => {
  it('recognizes version and authorization-generation conflicts', () => {
    expect(
      rbacConflict([
        {
          message: 'stale',
          kind: 'conflict',
          code: 19004,
          fields: [{ path: 'input.expectedVersion', code: 19004 }],
          extensions: {
            params: { current_version: '9f0c2b1a-3d4e-4f50-8a9b-1c2d3e4f5a6b' },
          },
        },
      ]),
    ).toEqual({
      conflict: true,
      currentVersion: '9f0c2b1a-3d4e-4f50-8a9b-1c2d3e4f5a6b',
    })

    expect(
      rbacConflict([
        {
          message: 'role name already exists',
          kind: 'conflict',
          code: 'role_name_conflict',
          fields: [{ path: 'input.names', message: 'Taken' }],
        },
      ]),
    ).toEqual({ conflict: false })
  })

  it('flattens field paths without turning ordinary validation into conflict', () => {
    const issues = [
      {
        message: 'invalid',
        fields: [
          { path: 'input.name', message: 'Name is required' },
          { path: 'input.reason', message: 'Reason is required' },
        ],
      },
    ]
    expect(hasFieldErrors(issues)).toBe(true)
    expect(rbacFieldErrors(issues)).toEqual({
      name: 'Name is required',
      reason: 'Reason is required',
    })
    expect(rbacConflict(issues).conflict).toBe(false)
  })
})
