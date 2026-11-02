// @vitest-environment node
import { describe, expect, it } from 'vitest'

import {
  DEFAULT_GROUP_ORDER,
  groupsFilterDraft,
  groupsQueryVariables,
  groupsSearchFromDraft,
  normalizeGroupsSearch,
} from '#/modules/user-management/groups/lib/groups-search'

describe('group directory search', () => {
  it('normalizes untrusted URL values and preserves explicit sorting', () => {
    expect(
      normalizeGroupsSearch({
        q: '  operators  ',
        builtIn: 'builtin',
        enabled: 'disabled',
        order: 'CREATED_AT_ASC',
        after: 'cursor-a',
        unexpected: 'ignored',
      }),
    ).toEqual({
      q: 'operators',
      enabled: 'disabled',
      order: 'CREATED_AT_ASC',
      after: 'cursor-a',
    })

    expect(
      normalizeGroupsSearch({
        q: '   ',
        builtIn: 'any',
        enabled: 'any',
        order: DEFAULT_GROUP_ORDER,
      }),
    ).toEqual({ order: DEFAULT_GROUP_ORDER })
  })

  it('serializes visible filters and explicit sorting', () => {
    expect(
      groupsQueryVariables({
        q: 'support',
        enabled: 'enabled',
        order: 'CREATED_AT_ASC',
      }),
    ).toEqual({
      filter: { query: 'support', enabled: true },
      orderBy: 'CREATED_AT_ASC',
      first: 10,
    })
  })

  it('does not preserve pagination when applying a filter draft', () => {
    for (const order of [undefined, DEFAULT_GROUP_ORDER]) {
      const search = groupsSearchFromDraft(
        groupsFilterDraft({ q: 'kept', order, after: 'old-page' }),
      )
      expect(normalizeGroupsSearch({ ...search }).order).toBe(order)
      expect(search.q).toBe('kept')
      expect(search.after).toBeUndefined()
      expect(search.before).toBeUndefined()
    }

    expect(
      groupsSearchFromDraft(
        groupsFilterDraft({
          q: 'ops',
          enabled: 'disabled',
          order: 'CREATED_AT_ASC',
          after: 'cursor',
        }),
      ),
    ).toEqual({
      q: 'ops',
      enabled: 'disabled',
      order: 'CREATED_AT_ASC',
    })
  })
})
