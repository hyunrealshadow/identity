import type { ResourceOrder } from '#/generated/graphql'
import { parsePageSize } from '#/lib/page-size'
import { cursorPage } from '#/modules/user-management/lib/cursor-page'

export const RESOURCES_PAGE_SIZE = 10

export interface ResourcesSearch {
  q?: string
  enabled?: 'enabled' | 'disabled'
  order?: ResourceOrder
  size?: number
  after?: string
  before?: string
}
const orders: readonly string[] = [
  'NAME_ASC',
  'NAME_DESC',
  'URI_ASC',
  'URI_DESC',
  'CREATED_AT_ASC',
  'CREATED_AT_DESC',
]
export function normalizeResourcesSearch(
  input: Record<string, unknown>,
): ResourcesSearch {
  return {
    q:
      typeof input.q === 'string' && input.q.trim()
        ? input.q.trim().slice(0, 256)
        : undefined,
    enabled:
      input.enabled === 'enabled' || input.enabled === 'disabled'
        ? input.enabled
        : undefined,
    order:
      typeof input.order === 'string' && orders.includes(input.order)
        ? (input.order as ResourceOrder)
        : undefined,
    size: parsePageSize(input.size),
    after: typeof input.after === 'string' ? input.after : undefined,
    before: typeof input.before === 'string' ? input.before : undefined,
  }
}
export function resourcesQueryVariables(search: ResourcesSearch) {
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
    orderBy: search.order ?? ('NAME_ASC' as ResourceOrder),
    ...cursorPage(search.size ?? RESOURCES_PAGE_SIZE, search.after, search.before),
  }
}
