import type { ClientOrder } from '#/generated/graphql'
import { cursorPage } from '#/modules/user-management/lib/cursor-page'

export interface ClientsSearch {
  q?: string
  enabled?: 'enabled' | 'disabled'
  order?: ClientOrder
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
    q:
      typeof input.q === 'string' && input.q.trim()
        ? input.q.trim().slice(0, 255)
        : undefined,
    enabled:
      input.enabled === 'enabled' || input.enabled === 'disabled'
        ? input.enabled
        : undefined,
    order:
      typeof input.order === 'string' && orders.includes(input.order)
        ? (input.order as ClientOrder)
        : undefined,
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
    ...cursorPage(CLIENTS_PAGE_SIZE, search.after, search.before),
  }
}
