import type { GroupFilter, GroupOrder } from '#/generated/graphql'
import { parsePageSize } from '#/lib/page-size'
import { cursorPage } from '#/modules/user-management/lib/cursor-page'
import {
  resolveLocalizedValue,
  type LocalizedValue,
} from '#/modules/user-management/lib/localized-metadata'

export const GROUP_PAGE_SIZE = 10

export type GroupEnabledFilter = 'any' | 'enabled' | 'disabled'
export type GroupOrderValue = Extract<
  GroupOrder,
  'CREATED_AT_ASC' | 'CREATED_AT_DESC'
>

export interface GroupsSearch {
  q?: string
  enabled?: GroupEnabledFilter
  order?: GroupOrderValue
  size?: number
  after?: string
  before?: string
}

export interface GroupsFilterDraft {
  q: string
  enabled: GroupEnabledFilter
  order?: GroupOrderValue
}

export const DEFAULT_GROUP_ORDER: GroupOrderValue = 'CREATED_AT_DESC'

const ORDERS: ReadonlyArray<GroupOrderValue> = [
  'CREATED_AT_DESC',
  'CREATED_AT_ASC',
]

export function isGroupOrder(value: unknown): value is GroupOrderValue {
  return typeof value === 'string' && ORDERS.includes(value as GroupOrderValue)
}

function isEnabled(value: unknown): value is GroupEnabledFilter {
  return value === 'any' || value === 'enabled' || value === 'disabled'
}

export function normalizeGroupsSearch(
  search: Record<string, unknown>,
): GroupsSearch {
  const result: GroupsSearch = {}
  // Typed text stays as the form holds it; it is trimmed when applied.
  if (typeof search.q === 'string' && search.q) {
    result.q = search.q.slice(0, 256)
  }
  if (isEnabled(search.enabled) && search.enabled !== 'any') {
    result.enabled = search.enabled
  }
  if (isGroupOrder(search.order)) {
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

export function groupsFilterDraft(search: GroupsSearch): GroupsFilterDraft {
  return {
    q: search.q ?? '',
    enabled: search.enabled ?? 'any',
    order: search.order,
  }
}

export function groupsSearchFromDraft(draft: GroupsFilterDraft): GroupsSearch {
  const result: GroupsSearch = {}
  if (draft.q.trim()) result.q = draft.q.trim()
  if (draft.enabled !== 'any') result.enabled = draft.enabled
  if (draft.order !== undefined) result.order = draft.order
  return result
}

export type GroupsFilters = Pick<GroupsSearch, 'q' | 'enabled'>

/** The form as it is written to the URL, without normalising typed text. */
export function groupsFormSearch(draft: GroupsFilterDraft): GroupsFilters {
  return {
    q: draft.q || undefined,
    enabled: draft.enabled === 'any' ? undefined : draft.enabled,
  }
}

/** The filters a query is sent with: the form's values, trimmed. */
export function groupsAppliedFilters(search: GroupsSearch): GroupsFilters {
  return { q: search.q?.trim() || undefined, enabled: search.enabled }
}

export function hasGroupFilters(search: GroupsSearch): boolean {
  return Boolean(search.q || search.enabled)
}

export function groupsFilter(search: GroupsSearch): GroupFilter {
  const filter: GroupFilter = {}
  if (search.q) filter.query = search.q
  if (search.enabled === 'enabled') filter.enabled = true
  if (search.enabled === 'disabled') filter.enabled = false
  return filter
}

export function groupsQueryVariables(search: GroupsSearch): {
  filter: GroupFilter
  orderBy: GroupOrder
  first?: number
  last?: number
  after?: string
  before?: string
} {
  return {
    filter: groupsFilter(search),
    orderBy: search.order ?? DEFAULT_GROUP_ORDER,
    ...cursorPage(search.size ?? GROUP_PAGE_SIZE, search.after, search.before),
  }
}

export function nextGroupsPage(
  search: GroupsSearch,
  endCursor: string,
): GroupsSearch {
  return { ...search, after: endCursor, before: undefined }
}

export function previousGroupsPage(
  search: GroupsSearch,
  startCursor: string,
): GroupsSearch {
  return { ...search, before: startCursor, after: undefined }
}

export function groupsSearchKey(search: GroupsSearch): string {
  return JSON.stringify(normalizeGroupsSearch({ ...search }))
}

export type LocalizedEntry = LocalizedValue

/**
 * Display text never participates in authorization. Resolution follows the
 * wording locale, its parent tags, en-US, then the first non-empty entry.
 */
export function resolveLocalizedText(
  entries: ReadonlyArray<LocalizedEntry> | null | undefined,
  locale: string,
): string | undefined {
  return resolveLocalizedValue(entries, locale)
}
