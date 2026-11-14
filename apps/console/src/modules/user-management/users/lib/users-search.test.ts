// @vitest-environment node
import { describe, expect, it } from 'vitest'

import {
  usersAppliedFilters,
  usersQueryVariables,
  usersFilterDraft,
  usersFormSearch,
  usersSearchFromDraft,
  usersSearchIssues,
  validateUsersSearch,
  type UsersFilterDraft,
} from '#/modules/user-management/users/lib/users-search'

function draft(overrides: Partial<UsersFilterDraft> = {}): UsersFilterDraft {
  return {
    q: '',
    username: '',
    email: '',
    enabled: 'any',
    locked: 'any',
    createdFrom: '',
    createdTo: '',
    order: 'CREATED_AT_DESC',
    ...overrides,
  }
}

describe('users search', () => {
  it('normalizes untrusted URL values and conflicting cursors', () => {
    const search = validateUsersSearch({
      q: '  ada  ',
      enabled: 'false',
      locked: 'nope',
      order: 'UNKNOWN',
      after: ' after ',
      before: 'before',
    })

    expect(search).toEqual({
      // Typed text stays exactly as the form holds it.
      q: '  ada  ',
      username: undefined,
      email: undefined,
      enabled: false,
      locked: undefined,
      createdFrom: undefined,
      createdTo: undefined,
      order: undefined,
      after: 'after',
      before: undefined,
    })
    // Text is trimmed only when the filters are applied.
    expect(usersAppliedFilters(search).q).toBe('ada')
  })

  it('keeps the form in the URL exactly as typed, including spaces', () => {
    const form = usersFormSearch(draft({ q: 'ada lovelace ', enabled: 'true' }))
    expect(form).toMatchObject({ q: 'ada lovelace ', enabled: true })
    // Round-trips through the URL without losing the trailing space.
    expect(usersFilterDraft(validateUsersSearch({ ...form })).q).toBe(
      'ada lovelace ',
    )
  })

  it('starts a new page when applying filters', () => {
    for (const order of [undefined, 'CREATED_AT_DESC'] as const) {
      const search = usersSearchFromDraft(
        usersFilterDraft({ q: 'kept', order, after: 'old-page' }),
      )
      expect(validateUsersSearch({ ...search }).order).toBe(order)
      expect(search.q).toBe('kept')
      expect(search.after).toBeUndefined()
      expect(search.before).toBeUndefined()
    }

    const search = usersSearchFromDraft(
      draft({ q: 'ada', enabled: 'true', createdFrom: '2026-01-01' }),
    )

    expect(search).toMatchObject({
      q: 'ada',
      enabled: true,
      createdFrom: '2026-01-01',
    })
    expect(search.after).toBeUndefined()
    expect(search.before).toBeUndefined()
  })

  it('uses forward and backward keyset arguments without mixing them', () => {
    const forward = usersQueryVariables(
      validateUsersSearch({ q: 'ada', after: 'cursor-a' }),
    )
    expect(forward).toMatchObject({ first: 10, after: 'cursor-a' })
    expect(forward?.last).toBeUndefined()

    const backward = usersQueryVariables(
      validateUsersSearch({ q: 'ada', before: 'cursor-b' }),
    )
    expect(backward).toMatchObject({ last: 10, before: 'cursor-b' })
    expect(backward?.first).toBeUndefined()
  })

  it('rejects reversed or invalid date ranges before querying', () => {
    expect(
      usersSearchIssues(
        validateUsersSearch({
          createdFrom: '2026-02-01',
          createdTo: '2026-01-01',
        }),
      ),
    ).toContain('createdRange')

    // Both ends are inclusive, so a single day is a valid range.
    expect(
      usersSearchIssues(
        validateUsersSearch({
          createdFrom: '2026-01-01',
          createdTo: '2026-01-01',
        }),
      ),
    ).toEqual([])

    expect(
      usersSearchIssues(validateUsersSearch({ createdFrom: '2026-02-30' })),
    ).toContain('createdFrom')
  })
})
