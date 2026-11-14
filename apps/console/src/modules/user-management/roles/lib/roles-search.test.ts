// @vitest-environment node
import { describe, expect, it } from 'vitest'

import {
  DEFAULT_ROLE_ORDER,
  normalizeRolesSearch,
  nextRolesPage,
  rolesAppliedFilters,
  previousRolesPage,
  rolesFilterDraft,
  rolesQueryVariables,
  rolesSearchFromDraft,
} from '#/modules/user-management/roles/lib/roles-search'

describe('role directory search', () => {
  it('normalizes untrusted URL values and preserves explicit sorting', () => {
    expect(
      normalizeRolesSearch({
        q: '  billing  ',
        status: 'disabled',
        order: 'NAME_DESC',
        after: 'cursor-a',
        before: 'cursor-b',
        unexpected: 'ignored',
      }),
    ).toEqual({
      // Typed text stays exactly as the form holds it.
      q: '  billing  ',
      status: 'disabled',
      order: 'NAME_DESC',
      after: 'cursor-a',
      before: 'cursor-b',
    })

    expect(
      normalizeRolesSearch({
        q: '   ',
        status: 'any',
        order: DEFAULT_ROLE_ORDER,
      }),
    ).toEqual({ q: '   ', order: DEFAULT_ROLE_ORDER })
  })

  it('trims typed text only when the filters are applied', () => {
    expect(rolesAppliedFilters({ q: '  billing  ' }).q).toBe('billing')
    expect(rolesAppliedFilters({ q: '   ' }).q).toBeUndefined()
  })

  it('builds bounded filter variables without inventing status', () => {
    expect(
      rolesQueryVariables({
        q: 'support',
        status: 'enabled',
        order: 'NAME_DESC',
      }),
    ).toEqual({
      filter: { query: 'support', enabled: true },
      orderBy: 'NAME_DESC',
      first: 10,
    })

    expect(rolesQueryVariables({ status: 'disabled' })).toEqual({
      filter: { enabled: false },
      orderBy: 'NAME_ASC',
      first: 10,
    })
  })

  it('returns next, previous, then next while preserving filters and clearing the opposite cursor', () => {
    const next = nextRolesPage({ q: 'x' }, 'page-one-end')
    expect(rolesQueryVariables(next)).toEqual({
      filter: { query: 'x' },
      orderBy: 'NAME_ASC',
      first: 10,
      after: 'page-one-end',
    })
    const back = previousRolesPage(next, 'page-two-start')
    expect(rolesQueryVariables(back)).toEqual({
      filter: { query: 'x' },
      orderBy: 'NAME_ASC',
      last: 10,
      before: 'page-two-start',
    })
    expect(rolesQueryVariables(nextRolesPage(back, 'page-one-end'))).toEqual(
      rolesQueryVariables(next),
    )
  })

  it('round-trips a visible filter draft without preserving pagination', () => {
    for (const order of [undefined, DEFAULT_ROLE_ORDER]) {
      const search = rolesSearchFromDraft(
        rolesFilterDraft({ q: 'kept', order, after: 'old-page' }),
      )
      expect(normalizeRolesSearch({ ...search }).order).toBe(order)
      expect(search.q).toBe('kept')
      expect(search.after).toBeUndefined()
      expect(search.before).toBeUndefined()
    }

    expect(
      rolesSearchFromDraft(
        rolesFilterDraft({
          q: 'ops',
          status: 'disabled',
          order: 'CREATED_AT_DESC',
          after: 'cursor',
        }),
      ),
    ).toEqual({
      q: 'ops',
      status: 'disabled',
      order: 'CREATED_AT_DESC',
    })
  })
})
