// @vitest-environment node
import { describe, expect, it } from 'vitest'

import {
  initialPermissionSelection,
  rolePermissionSubmitAvailability,
  selectionDiff,
  togglePermission,
  type PermissionMembershipState,
} from '#/modules/user-management/roles/lib/permission-selection'

const complete: PermissionMembershipState = {
  status: 'ready',
  ids: new Set(['p1', 'p2', 'p3']),
  loadedPages: 2,
  hasNextPage: false,
}

describe('role permission replacement', () => {
  it('never initializes selection from an incomplete membership snapshot', () => {
    expect(
      initialPermissionSelection({
        ...complete,
        hasNextPage: true,
      }).size,
    ).toBe(0)
    expect(
      initialPermissionSelection({
        ...complete,
        loadedPages: 0,
      }).size,
    ).toBe(0)
    expect([...initialPermissionSelection(complete)]).toEqual([
      'p1',
      'p2',
      'p3',
    ])
  })

  it('toggles without mutating the previous set', () => {
    const selected = new Set(['p1'])
    const next = togglePermission(selected, 'p2')
    expect([...selected]).toEqual(['p1'])
    expect([...next]).toEqual(['p1', 'p2'])
    expect([...togglePermission(next, 'p1')]).toEqual(['p2'])
  })

  it('derives deterministic additions and removals from the full set', () => {
    expect(
      selectionDiff(new Set(['p1', 'p2']), new Set(['p2', 'p3'])),
    ).toEqual({ added: ['p3'], removed: ['p1'] })
  })

  it('blocks submission until every page and the catalog are ready', () => {
    const initial = new Set(['p1'])
    const selected = new Set(['p1', 'p2'])
    expect(
      rolePermissionSubmitAvailability({
        membership: { ...complete, hasNextPage: true },
        catalogStatus: 'ready',
        initial,
        selected,
      }),
    ).toEqual({ allowed: false, reason: 'membership-incomplete' })

    expect(
      rolePermissionSubmitAvailability({
        membership: complete,
        catalogStatus: 'error',
        initial,
        selected,
      }),
    ).toEqual({ allowed: false, reason: 'catalog-error' })

    expect(
      rolePermissionSubmitAvailability({
        membership: complete,
        catalogStatus: 'ready',
        initial,
        selected,
      }),
    ).toEqual({ allowed: true, reason: 'ready' })
  })

  it('allows clearing every permission without an additional input', () => {
    expect(
      rolePermissionSubmitAvailability({
        membership: complete,
        catalogStatus: 'ready',
        initial: new Set(['p1', 'p2']),
        selected: new Set(),
      }),
    ).toEqual({ allowed: true, reason: 'ready' })

    expect(
      rolePermissionSubmitAvailability({
        membership: complete,
        catalogStatus: 'ready',
        initial: new Set(),
        selected: new Set(),
      }),
    ).toEqual({ allowed: false, reason: 'no-changes' })
  })
})
