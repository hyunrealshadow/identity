import { cursorPage } from '#/modules/user-management/lib/cursor-page'

export const ROLE_PAGE_SIZE = 10

export type RoleStatusFilter = 'any' | 'enabled' | 'disabled'
export type RoleOrderValue =
  'CREATED_AT_DESC' | 'CREATED_AT_ASC' | 'NAME_ASC' | 'NAME_DESC'

export interface RolesSearch {
  q?: string
  status?: RoleStatusFilter
  order?: RoleOrderValue
  after?: string
  before?: string
}

export interface RolesFilterDraft {
  q: string
  status: RoleStatusFilter
  order?: RoleOrderValue
}

export const DEFAULT_ROLE_ORDER: RoleOrderValue = 'NAME_ASC'

const ORDERS: ReadonlyArray<RoleOrderValue> = [
  'CREATED_AT_DESC',
  'CREATED_AT_ASC',
  'NAME_ASC',
  'NAME_DESC',
]

export function isRoleOrder(value: unknown): value is RoleOrderValue {
  return typeof value === 'string' && ORDERS.includes(value as RoleOrderValue)
}

function isStatus(value: unknown): value is RoleStatusFilter {
  return value === 'any' || value === 'enabled' || value === 'disabled'
}

export function normalizeRolesSearch(
  search: Record<string, unknown>,
): RolesSearch {
  const result: RolesSearch = {}
  if (typeof search.q === 'string' && search.q.trim()) {
    result.q = search.q.trim().slice(0, 256)
  }
  if (isStatus(search.status) && search.status !== 'any') {
    result.status = search.status
  }
  if (isRoleOrder(search.order)) {
    result.order = search.order
  }
  if (typeof search.after === 'string' && search.after) {
    result.after = search.after
  }
  if (typeof search.before === 'string' && search.before) {
    result.before = search.before
  }
  return result
}

export function rolesFilterDraft(search: RolesSearch): RolesFilterDraft {
  return {
    q: search.q ?? '',
    status: search.status ?? 'any',
    order: search.order,
  }
}

export function rolesSearchFromDraft(draft: RolesFilterDraft): RolesSearch {
  const result: RolesSearch = {}
  if (draft.q.trim()) result.q = draft.q.trim()
  if (draft.status !== 'any') result.status = draft.status
  if (draft.order !== undefined) result.order = draft.order
  return result
}

export function hasRoleFilters(search: RolesSearch): boolean {
  return Boolean(search.q || search.status)
}

export function rolesQueryVariables(search: RolesSearch): {
  filter: { query?: string; enabled?: boolean }
  orderBy: RoleOrderValue
  first?: number
  last?: number
  after?: string
  before?: string
} {
  const filter: { query?: string; enabled?: boolean } = {}
  if (search.q) filter.query = search.q
  if (search.status === 'enabled') filter.enabled = true
  if (search.status === 'disabled') filter.enabled = false
  const variables: {
    filter: { query?: string; enabled?: boolean }
    orderBy: RoleOrderValue
    first?: number
    last?: number
    after?: string
    before?: string
  } = {
    filter,
    orderBy: search.order ?? DEFAULT_ROLE_ORDER,
    ...cursorPage(ROLE_PAGE_SIZE, search.after, search.before),
  }
  return variables
}

export function nextRolesPage(
  search: RolesSearch,
  endCursor: string,
): RolesSearch {
  return { ...search, after: endCursor, before: undefined }
}

export function previousRolesPage(
  search: RolesSearch,
  startCursor: string,
): RolesSearch {
  return { ...search, before: startCursor, after: undefined }
}

export function rolesSearchKey(search: RolesSearch): string {
  return JSON.stringify(normalizeRolesSearch({ ...search }))
}
