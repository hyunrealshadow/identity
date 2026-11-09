import { parsePageSize } from '#/lib/page-size'
import { cursorPage } from '#/modules/user-management/lib/cursor-page'

export const PERMISSION_PAGE_SIZE = 100

export type PermissionBuiltInFilter = 'any' | 'true' | 'false'
export type PermissionEnabledFilter = 'any' | 'enabled' | 'disabled'
export type PermissionOrderValue =
  'CODE_ASC' | 'CODE_DESC' | 'CREATED_AT_ASC' | 'CREATED_AT_DESC'

export interface PermissionsSearch {
  q?: string
  resourceId?: string
  builtIn?: PermissionBuiltInFilter
  enabled?: PermissionEnabledFilter
  order?: PermissionOrderValue
  size?: number
  after?: string
  before?: string
}

export interface PermissionsFilterDraft {
  q: string
  resourceId: string
  builtIn: PermissionBuiltInFilter
  enabled: PermissionEnabledFilter
  order?: PermissionOrderValue
}

export const DEFAULT_PERMISSION_ORDER: PermissionOrderValue = 'CODE_ASC'

const ORDERS: ReadonlyArray<PermissionOrderValue> = [
  'CODE_ASC',
  'CODE_DESC',
  'CREATED_AT_ASC',
  'CREATED_AT_DESC',
]

export function isPermissionOrder(
  value: unknown,
): value is PermissionOrderValue {
  return (
    typeof value === 'string' && ORDERS.includes(value as PermissionOrderValue)
  )
}

function isBuiltInFilter(value: unknown): value is PermissionBuiltInFilter {
  return value === 'any' || value === 'true' || value === 'false'
}

function isEnabledFilter(value: unknown): value is PermissionEnabledFilter {
  return value === 'any' || value === 'enabled' || value === 'disabled'
}

export function normalizePermissionsSearch(
  search: Record<string, unknown>,
): PermissionsSearch {
  const result: PermissionsSearch = {}
  if (typeof search.q === 'string' && search.q.trim()) {
    result.q = search.q.trim().slice(0, 256)
  }
  if (typeof search.resourceId === 'string' && search.resourceId.trim()) {
    result.resourceId = search.resourceId.trim()
  }
  if (isBuiltInFilter(search.builtIn) && search.builtIn !== 'any') {
    result.builtIn = search.builtIn
  }
  if (isEnabledFilter(search.enabled) && search.enabled !== 'any') {
    result.enabled = search.enabled
  }
  if (isPermissionOrder(search.order)) {
    result.order = search.order
  }
  const size = parsePageSize(search.size)
  if (size !== undefined) result.size = size
  if (typeof search.after === 'string' && search.after) {
    result.after = search.after
  }
  if (typeof search.before === 'string' && search.before) {
    result.before = search.before
  }
  return result
}

export function permissionsFilterDraft(
  search: PermissionsSearch,
): PermissionsFilterDraft {
  return {
    q: search.q ?? '',
    resourceId: search.resourceId ?? '',
    builtIn: search.builtIn ?? 'any',
    enabled: search.enabled ?? 'any',
    order: search.order,
  }
}

/**
 * Applying filters or changing the order always starts a fresh page, so no
 * cursor from the previous result set survives the change.
 */
export function permissionsSearchFromDraft(
  draft: PermissionsFilterDraft,
): PermissionsSearch {
  const result: PermissionsSearch = {}
  if (draft.q.trim()) result.q = draft.q.trim()
  if (draft.resourceId.trim()) result.resourceId = draft.resourceId.trim()
  if (draft.builtIn !== 'any') result.builtIn = draft.builtIn
  if (draft.enabled !== 'any') result.enabled = draft.enabled
  if (draft.order !== undefined) result.order = draft.order
  return result
}

export function hasPermissionFilters(search: PermissionsSearch): boolean {
  return Boolean(
    search.q || search.resourceId || search.builtIn || search.enabled,
  )
}

export interface PermissionFilterVariables {
  apiOnly: boolean
  query?: string
  resourceId?: string
  builtIn?: boolean
  enabled?: boolean
}

export interface PermissionsQueryVariables {
  filter: PermissionFilterVariables
  orderBy: PermissionOrderValue
  first?: number
  last?: number
  after?: string
  before?: string
  includeResource: boolean
}

export function permissionsQueryVariables(
  search: PermissionsSearch,
  options: { includeResource: boolean },
): PermissionsQueryVariables {
  const filter: PermissionFilterVariables = { apiOnly: true }
  if (search.q) filter.query = search.q
  if (search.resourceId) filter.resourceId = search.resourceId
  if (search.builtIn === 'true') filter.builtIn = true
  if (search.builtIn === 'false') filter.builtIn = false
  if (search.enabled === 'enabled') filter.enabled = true
  if (search.enabled === 'disabled') filter.enabled = false

  return {
    filter,
    orderBy: search.order ?? DEFAULT_PERMISSION_ORDER,
    ...cursorPage(search.size ?? PERMISSION_PAGE_SIZE, search.after, search.before),
    includeResource: options.includeResource,
  }
}

export function nextPermissionsPage(
  search: PermissionsSearch,
  endCursor: string,
): PermissionsSearch {
  return { ...search, after: endCursor, before: undefined }
}

export function previousPermissionsPage(
  search: PermissionsSearch,
  startCursor: string,
): PermissionsSearch {
  return { ...search, before: startCursor, after: undefined }
}

export function permissionsSearchKey(search: PermissionsSearch): string {
  return JSON.stringify(normalizePermissionsSearch({ ...search }))
}

/** The resource route is authoritative even when a stale URL contains another resource. */
export function resourcePermissionsQueryVariables(
  resourceId: string,
  search: PermissionsSearch,
): PermissionsQueryVariables {
  const values = permissionsQueryVariables(search, { includeResource: false })
  return { ...values, filter: { ...values.filter, resourceId } }
}

/** Read-only resource definitions have no enabled-state filter or state-bound cursor. */
export function permissionsSearchForResource(
  search: PermissionsSearch,
  readOnly: boolean,
): PermissionsSearch {
  if (!readOnly || search.enabled === undefined) return search
  return { ...search, enabled: undefined, after: undefined, before: undefined }
}
