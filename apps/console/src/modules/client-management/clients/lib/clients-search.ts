import type { ClientOrder } from '#/generated/graphql'
import { parsePageSize } from '#/lib/page-size'
import { cursorPage } from '#/modules/user-management/lib/cursor-page'

export interface ClientsSearch {
  q?: string
  enabled?: 'enabled' | 'disabled'
  order?: ClientOrder
  size?: number
  after?: string
  before?: string
}

const orders: readonly string[] = [
  'NAME_ASC',
  'NAME_DESC',
  'CREATED_AT_ASC',
  'CREATED_AT_DESC',
]

export const CLIENTS_PAGE_SIZE = 10

export function normalizeClientsSearch(
  input: Record<string, unknown>,
): ClientsSearch {
  return {
    // Typed text stays as the form holds it; it is trimmed when applied.
    q:
      typeof input.q === 'string' && input.q
        ? input.q.slice(0, 255)
        : undefined,
    enabled:
      input.enabled === 'enabled' || input.enabled === 'disabled'
        ? input.enabled
        : undefined,
    order:
      typeof input.order === 'string' && orders.includes(input.order)
        ? (input.order as ClientOrder)
        : undefined,
    size: parsePageSize(input.size),
    after: typeof input.after === 'string' ? input.after : undefined,
    before: typeof input.before === 'string' ? input.before : undefined,
  }
}

export function clientsQueryVariables(search: ClientsSearch) {
  return {
    filter: {
      query: search.q || undefined,
      enabled:
        search.enabled === 'enabled'
          ? true
          : search.enabled === 'disabled'
            ? false
            : undefined,
    },
    orderBy: search.order ?? ('CREATED_AT_DESC' as ClientOrder),
    ...cursorPage(search.size ?? CLIENTS_PAGE_SIZE, search.after, search.before),
  }
}

export type ClientsFilters = Pick<ClientsSearch, 'q' | 'enabled'>

export function clientsSearchKey(search: ClientsSearch): string {
  return JSON.stringify(normalizeClientsSearch({ ...search }))
}

/** The filters a query is sent with: the form's values, trimmed. */
export function clientsAppliedFilters(search: ClientsSearch): ClientsFilters {
  return { q: search.q?.trim() || undefined, enabled: search.enabled }
}
