import { parsePageSize } from '#/lib/page-size'
import { startOfZonedDate } from '#/lib/time-zone'
import type {
  ConsoleUsersQueryVariables,
  UserFilter,
  UserOrder,
} from '#/generated/graphql'

export const USER_ORDERS = [
  'CREATED_AT_ASC',
  'CREATED_AT_DESC',
  'USERNAME_ASC',
  'USERNAME_DESC',
] as const satisfies ReadonlyArray<UserOrder>

export type UsersOrder = (typeof USER_ORDERS)[number]

export const DEFAULT_USERS_ORDER: UsersOrder = 'CREATED_AT_DESC'
// Keep the complete directory projection within the shared GraphQL cost budget.
export const USERS_PAGE_SIZE = 10

export const USERS_SEARCH_LIMITS = {
  query: 255,
  username: 64,
  email: 320,
} as const

export interface UsersSearch {
  q?: string
  username?: string
  email?: string
  enabled?: boolean
  locked?: boolean
  createdFrom?: string
  createdTo?: string
  order?: UsersOrder
  size?: number
  after?: string
  before?: string
}

export type UsersSearchIssue =
  | 'query'
  | 'username'
  | 'email'
  | 'createdFrom'
  | 'createdTo'
  | 'createdRange'

export type UsersFilterStatus = 'any' | 'true' | 'false'

export interface UsersFilterDraft {
  q: string
  username: string
  email: string
  enabled: UsersFilterStatus
  locked: UsersFilterStatus
  createdFrom: string
  createdTo: string
  order?: UsersOrder
}

export function emptyUsersFilterDraft(): UsersFilterDraft {
  return {
    q: '',
    username: '',
    email: '',
    enabled: 'any',
    locked: 'any',
    createdFrom: '',
    createdTo: '',
    order: undefined,
  }
}

function text(value: unknown): string | undefined {
  if (typeof value !== 'string') return undefined
  const trimmed = value.trim()
  return trimmed.length > 0 ? trimmed : undefined
}

/** Free text as typed: the URL keeps the form exactly, spaces included. */
function rawText(value: unknown): string | undefined {
  return typeof value === 'string' && value.length > 0 ? value : undefined
}

function booleanValue(value: unknown): boolean | undefined {
  if (value === true || value === 'true') return true
  if (value === false || value === 'false') return false
  return undefined
}

export function isUserOrder(value: unknown): value is UsersOrder {
  return (
    typeof value === 'string' &&
    (USER_ORDERS as ReadonlyArray<string>).includes(value)
  )
}

/**
 * Normalize untrusted URL search params. Invalid enum/boolean values are
 * ignored rather than forwarded to GraphQL, and conflicting cursors collapse
 * to a single direction.
 */
export function validateUsersSearch(raw: Record<string, unknown>): UsersSearch {
  const after = text(raw.after)
  const before = after ? undefined : text(raw.before)
  const order = isUserOrder(raw.order) ? raw.order : undefined

  return {
    q: rawText(raw.q),
    username: rawText(raw.username),
    email: rawText(raw.email),
    enabled: booleanValue(raw.enabled),
    locked: booleanValue(raw.locked),
    createdFrom: text(raw.createdFrom),
    createdTo: text(raw.createdTo),
    order,
    size: parsePageSize(raw.size),
    after,
    before,
  }
}

export function usersFilterDraft(search: UsersSearch): UsersFilterDraft {
  return {
    q: search.q ?? '',
    username: search.username ?? '',
    email: search.email ?? '',
    enabled:
      search.enabled === undefined ? 'any' : search.enabled ? 'true' : 'false',
    locked:
      search.locked === undefined ? 'any' : search.locked ? 'true' : 'false',
    createdFrom: search.createdFrom ?? '',
    createdTo: search.createdTo ?? '',
    order: search.order,
  }
}

function statusValue(value: UsersFilterStatus): boolean | undefined {
  if (value === 'true') return true
  if (value === 'false') return false
  return undefined
}

export type UsersFilters = Pick<
  UsersSearch,
  'q' | 'username' | 'email' | 'enabled' | 'locked' | 'createdFrom' | 'createdTo'
>

/** The form as it is written to the URL, without normalising typed text. */
export function usersFormSearch(draft: UsersFilterDraft): UsersFilters {
  return {
    q: draft.q || undefined,
    username: draft.username || undefined,
    email: draft.email || undefined,
    enabled: statusValue(draft.enabled),
    locked: statusValue(draft.locked),
    createdFrom: draft.createdFrom || undefined,
    createdTo: draft.createdTo || undefined,
  }
}

/** The filters a query is sent with: the form's values, trimmed. */
export function usersAppliedFilters(search: UsersSearch): UsersFilters {
  return {
    q: search.q?.trim() || undefined,
    username: search.username?.trim() || undefined,
    email: search.email?.trim() || undefined,
    enabled: search.enabled,
    locked: search.locked,
    createdFrom: search.createdFrom,
    createdTo: search.createdTo,
  }
}

/**
 * Build a fresh filter search from the form draft. Cursors are intentionally
 * dropped: every filter or ordering change starts a new keyset page.
 */
export function usersSearchFromDraft(draft: UsersFilterDraft): UsersSearch {
  return {
    q: draft.q.trim() || undefined,
    username: draft.username.trim() || undefined,
    email: draft.email.trim() || undefined,
    enabled: statusValue(draft.enabled),
    locked: statusValue(draft.locked),
    createdFrom: draft.createdFrom.trim() || undefined,
    createdTo: draft.createdTo.trim() || undefined,
    order: draft.order,
  }
}

function isIsoDate(value: string): boolean {
  if (!/^\d{4}-\d{2}-\d{2}$/.test(value)) return false
  const date = new Date(`${value}T00:00:00.000Z`)
  return (
    !Number.isNaN(date.getTime()) && date.toISOString().slice(0, 10) === value
  )
}

function nextIsoDate(value: string): string {
  const date = new Date(`${value}T00:00:00.000Z`)
  date.setUTCDate(date.getUTCDate() + 1)
  return date.toISOString().slice(0, 10)
}

export function usersSearchIssues(search: UsersSearch): UsersSearchIssue[] {
  const issues: UsersSearchIssue[] = []
  if ((search.q?.length ?? 0) > USERS_SEARCH_LIMITS.query) issues.push('query')
  if ((search.username?.length ?? 0) > USERS_SEARCH_LIMITS.username) {
    issues.push('username')
  }
  if ((search.email?.length ?? 0) > USERS_SEARCH_LIMITS.email) {
    issues.push('email')
  }

  const fromValid = search.createdFrom ? isIsoDate(search.createdFrom) : true
  const beforeValid = search.createdTo
    ? isIsoDate(search.createdTo)
    : true
  if (!fromValid) issues.push('createdFrom')
  if (!beforeValid) issues.push('createdTo')
  if (
    fromValid &&
    beforeValid &&
    search.createdFrom &&
    search.createdTo &&
    search.createdFrom > search.createdTo
  ) {
    issues.push('createdRange')
  }

  return issues
}

export function hasUserFilters(search: UsersSearch): boolean {
  return Boolean(
    search.q ||
    search.username ||
    search.email ||
    search.enabled !== undefined ||
    search.locked !== undefined ||
    search.createdFrom ||
    search.createdTo,
  )
}

export function userFilterFromSearch(
  search: UsersSearch,
  timeZone = 'UTC',
): UserFilter {
  const filter: UserFilter = {}
  if (search.q) filter.query = search.q
  if (search.username) filter.username = search.username
  if (search.email) filter.email = search.email
  if (search.enabled !== undefined) filter.enabled = search.enabled
  if (search.locked !== undefined) filter.locked = search.locked
  if (search.createdFrom) {
    filter.createdFrom = startOfZonedDate(search.createdFrom, timeZone)
  }
  if (search.createdTo) {
    // The end date is inclusive: the API bound is the start of the next day.
    filter.createdBefore = startOfZonedDate(nextIsoDate(search.createdTo), timeZone)
  }
  return filter
}

export function usersQueryVariables(
  search: UsersSearch,
  timeZone = 'UTC',
): ConsoleUsersQueryVariables | null {
  if (usersSearchIssues(search).length > 0) return null

  const filter = userFilterFromSearch(search, timeZone)
  const hasFilter = Object.keys(filter).length > 0
  const orderBy = search.order ?? DEFAULT_USERS_ORDER

  if (search.before) {
    return {
      filter: hasFilter ? filter : undefined,
      orderBy,
      last: search.size ?? USERS_PAGE_SIZE,
      before: search.before,
    }
  }

  return {
    filter: hasFilter ? filter : undefined,
    orderBy,
    first: search.size ?? USERS_PAGE_SIZE,
    after: search.after,
  }
}

export function usersSearchKey(search: UsersSearch): string {
  return JSON.stringify([
    search.q ?? '',
    search.username ?? '',
    search.email ?? '',
    search.enabled ?? null,
    search.locked ?? null,
    search.createdFrom ?? '',
    search.createdTo ?? '',
    search.order ?? DEFAULT_USERS_ORDER,
    search.size ?? USERS_PAGE_SIZE,
    search.after ?? '',
    search.before ?? '',
  ])
}

export function resetUsersCursors(search: UsersSearch): UsersSearch {
  const next = { ...search }
  delete next.after
  delete next.before
  return next
}

export function nextUsersPage(
  search: UsersSearch,
  endCursor: string,
): UsersSearch {
  const next = resetUsersCursors(search)
  next.after = endCursor
  return next
}

export function previousUsersPage(
  search: UsersSearch,
  startCursor: string,
): UsersSearch {
  const next = resetUsersCursors(search)
  next.before = startCursor
  return next
}
