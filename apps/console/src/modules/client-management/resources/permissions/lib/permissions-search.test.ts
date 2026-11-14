// @vitest-environment node
import { describe, expect, it } from 'vitest'

import {
  DEFAULT_PERMISSION_ORDER,
  permissionsSearchForResource,
  normalizePermissionsSearch,
  permissionsQueryVariables,
  resourcePermissionsQueryVariables,
  permissionsAppliedFilters,
  permissionsFilterDraft,
  permissionsSearchFromDraft,
} from '#/modules/client-management/resources/permissions/lib/permissions-search'

describe('permission search state', () => {
  it('drops a hidden state filter and its cursors only for read-only resources', () => {
    const search = {
      q: 'read',
      enabled: 'disabled' as const,
      after: 'filtered-cursor',
    }
    const readonly = permissionsSearchForResource(search, true)
    expect(
      resourcePermissionsQueryVariables('system', readonly).filter.enabled,
    ).toBeUndefined()
    expect(readonly.after).toBeUndefined()
    expect(readonly.q).toBe('read')
    const custom = permissionsSearchForResource(search, false)
    expect(
      resourcePermissionsQueryVariables('custom', custom).filter.enabled,
    ).toBe(false)
    expect(custom.after).toBe('filtered-cursor')
  })

  it('keeps queries in the route resource while preserving filters and reverse pagination', () => {
    const variables = resourcePermissionsQueryVariables('current-resource', {
      resourceId: 'stale-resource',
      q: 'read',
      enabled: 'disabled',
      before: 'previous',
    })
    expect(variables.filter).toEqual({
      apiOnly: true,
      resourceId: 'current-resource',
      query: 'read',
      enabled: false,
    })
    expect(variables.before).toBe('previous')
    expect(variables.last).toBeGreaterThan(0)
    expect(variables.first).toBeUndefined()
  })

  it('normalizes query, filters, and order while keeping valid cursors', () => {
    expect(
      normalizePermissionsSearch({
        q: '  users.read  ',
        resourceId: ' resource-1 ',
        builtIn: 'true',
        enabled: 'disabled',
        order: 'CREATED_AT_DESC',
        after: 'cursor-a',
        before: '',
      }),
    ).toEqual({
      // Typed text stays exactly as the form holds it.
      q: '  users.read  ',
      resourceId: 'resource-1',
      builtIn: 'true',
      enabled: 'disabled',
      order: 'CREATED_AT_DESC',
      after: 'cursor-a',
    })
  })

  it('drops unsupported filters while preserving an explicitly selected order', () => {
    expect(
      normalizePermissionsSearch({
        q: '   ',
        resourceId: '',
        builtIn: 'any',
        enabled: 'any',
        order: DEFAULT_PERMISSION_ORDER,
      }),
    ).toEqual({ q: '   ', order: DEFAULT_PERMISSION_ORDER })
    // Blank text is not a filter once applied.
    expect(permissionsAppliedFilters({ q: '   ' }).q).toBeUndefined()
    expect(permissionsAppliedFilters({ q: '  users.read  ' }).q).toBe(
      'users.read',
    )
    expect(
      normalizePermissionsSearch({
        builtIn: 'sometimes',
        enabled: 'never',
        order: 'NAME_ASC',
      }),
    ).toEqual({})
  })

  it('resets cursors whenever filters or order are applied', () => {
    for (const order of [undefined, DEFAULT_PERMISSION_ORDER]) {
      const search = permissionsSearchFromDraft(
        permissionsFilterDraft({ q: 'kept', order, after: 'old-page' }),
      )
      expect(normalizePermissionsSearch({ ...search }).order).toBe(order)
      expect(search.q).toBe('kept')
      expect(search.after).toBeUndefined()
      expect(search.before).toBeUndefined()
    }

    const next = permissionsSearchFromDraft({
      q: 'read',
      resourceId: 'resource-1',
      builtIn: 'false',
      enabled: 'enabled',
      order: 'CODE_DESC',
    })
    expect(next).toEqual({
      q: 'read',
      resourceId: 'resource-1',
      builtIn: 'false',
      enabled: 'enabled',
      order: 'CODE_DESC',
    })
    expect(next.after).toBeUndefined()
    expect(next.before).toBeUndefined()
  })

  it('maps filters to GraphQL booleans and requests resource details', () => {
    const first = permissionsQueryVariables(
      {
        builtIn: 'false',
        enabled: 'enabled',
        resourceId: 'resource-1',
        order: 'CODE_DESC',
      },
      { includeResource: true },
    )
    expect(first.filter).toEqual({
      apiOnly: true,
      resourceId: 'resource-1',
      builtIn: false,
      enabled: true,
    })
    expect(first.orderBy).toBe('CODE_DESC')
    expect(first.includeResource).toBe(true)
  })
})
