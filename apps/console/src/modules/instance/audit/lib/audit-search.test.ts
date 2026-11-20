import { describe, expect, it } from 'vitest'

import {
  AUDIT_EVENTS_PAGE_SIZE,
  auditEventsQueryKey,
  auditEventsQueryVariables,
  auditEventsSearchKey,
  normalizeAuditEventsSearch,
} from './audit-search'

describe('audit-search', () => {
  it('normalizes valid search parameters and bounds long queries', () => {
    const normalized = normalizeAuditEventsSearch({
      q: 'action:user.*',
      event: 'QXVkaXRFdmVudDox',
      order: 'OCCURRED_AT_ASC',
      size: '50',
      after: 'cursor-1',
    })

    expect(normalized).toEqual({
      q: 'action:user.*',
      event: 'QXVkaXRFdmVudDox',
      order: 'OCCURRED_AT_ASC',
      size: 50,
      after: 'cursor-1',
      before: undefined,
    })

    expect(
      normalizeAuditEventsSearch({ q: 'a'.repeat(3000), order: 'BOGUS' }),
    ).toEqual({
      q: 'a'.repeat(2048),
      event: undefined,
      order: undefined,
      size: undefined,
      after: undefined,
      before: undefined,
    })
  })

  it('builds GraphQL variables with user time zone and actor include flags', () => {
    const vars = auditEventsQueryVariables(
      'SIGN_IN',
      { q: ' outcome:failure ', size: 50, after: 'cur-2' },
      'Asia/Shanghai',
      { includeActorUser: true, includeActorClient: false },
    )

    expect(vars).toEqual({
      category: 'SIGN_IN',
      query: 'outcome:failure',
      timeZone: 'Asia/Shanghai',
      orderBy: 'OCCURRED_AT_DESC',
      first: 50,
      after: 'cur-2',
      includeActorUser: true,
      includeActorClient: false,
    })

    const defaultVars = auditEventsQueryVariables(undefined, {}, 'UTC', {
      includeActorUser: false,
      includeActorClient: false,
    })
    expect(defaultVars.first).toBe(AUDIT_EVENTS_PAGE_SIZE)
    expect(defaultVars.query).toBeUndefined()
    expect(defaultVars.category).toBeUndefined()
  })

  it('distinguishes detail selection and trailing query spaces in search key while ignoring them in query key', () => {
    expect(
      auditEventsSearchKey({ q: 'action:user_create' }),
    ).not.toBe(
      auditEventsSearchKey({
        q: 'action:user_create',
        event: 'QXVkaXRFdmVudDox',
      }),
    )

    expect(auditEventsSearchKey({ q: 'action:user_create ' })).not.toBe(
      auditEventsSearchKey({ q: 'action:user_create' }),
    )

    expect(
      auditEventsQueryKey({ q: 'action:user_create' } as Parameters<
        typeof auditEventsQueryKey
      >[0]),
    ).toBe(
      auditEventsQueryKey({
        q: ' action:user_create ',
        event: 'QXVkaXRFdmVudDox',
      } as Parameters<typeof auditEventsQueryKey>[0]),
    )
  })
})
