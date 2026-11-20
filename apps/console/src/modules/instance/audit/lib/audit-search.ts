import type { AuditEventOrder } from '#/generated/graphql'
import { parsePageSize } from '#/lib/page-size'
import { cursorPage } from '#/modules/user-management/lib/cursor-page'

export const AUDIT_EVENTS_PAGE_SIZE = 20
const MAX_AUDIT_QUERY_CHARS = 2048

export interface AuditEventsSearch {
  q?: string
  event?: string
  order?: AuditEventOrder
  size?: number
  after?: string
  before?: string
}

const orders: readonly string[] = ['OCCURRED_AT_ASC', 'OCCURRED_AT_DESC']

export function normalizeAuditEventsSearch(
  input: Record<string, unknown>,
): AuditEventsSearch {
  return {
    q:
      typeof input.q === 'string' && input.q
        ? input.q.slice(0, MAX_AUDIT_QUERY_CHARS)
        : undefined,
    event: typeof input.event === 'string' && input.event.trim() ? input.event.trim() : undefined,
    order:
      typeof input.order === 'string' && orders.includes(input.order)
        ? (input.order as AuditEventOrder)
        : undefined,
    size: parsePageSize(input.size),
    after: typeof input.after === 'string' && input.after ? input.after : undefined,
    before: typeof input.before === 'string' && input.before ? input.before : undefined,
  }
}

export function auditEventsQueryVariables(
  search: AuditEventsSearch,
  timeZone: string,
  options: { includeActorUser: boolean; includeActorClient: boolean },
) {
  return {
    query: search.q?.trim() || undefined,
    timeZone,
    orderBy: search.order ?? ('OCCURRED_AT_DESC' as AuditEventOrder),
    ...cursorPage(search.size ?? AUDIT_EVENTS_PAGE_SIZE, search.after, search.before),
    includeActorUser: options.includeActorUser,
    includeActorClient: options.includeActorClient,
  }
}

export type AuditEventsFilters = Pick<AuditEventsSearch, 'q'>

export function auditEventsSearchKey(search: AuditEventsSearch): string {
  return JSON.stringify(normalizeAuditEventsSearch({ ...search }))
}

export function auditEventsQueryKey(
  search: Pick<AuditEventsSearch, 'q' | 'order' | 'size' | 'after' | 'before'>,
): string {
  return JSON.stringify({
    q: search.q?.trim() || undefined,
    order: search.order ?? 'OCCURRED_AT_DESC',
    size: search.size ?? AUDIT_EVENTS_PAGE_SIZE,
    after: search.after || undefined,
    before: search.before || undefined,
  })
}

export function auditEventsAppliedFilters(search: AuditEventsSearch): AuditEventsFilters {
  return { q: search.q?.trim() || undefined }
}
