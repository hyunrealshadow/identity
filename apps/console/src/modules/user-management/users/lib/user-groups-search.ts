import { parsePageSize } from '#/lib/page-size'

export const USER_GROUPS_PAGE_SIZE = 10

/** URL search of a user's group list; it mirrors the filter form. */
export interface UserGroupsSearch {
  q?: string
  size?: number
  after?: string
  before?: string
}

export interface UserGroupsFilters {
  q?: string
}

export function normalizeUserGroupsSearch(
  input: Record<string, unknown>,
): UserGroupsSearch {
  const result: UserGroupsSearch = {}
  // Typed text stays as the form holds it; it is trimmed when applied.
  if (typeof input.q === 'string' && input.q) result.q = input.q.slice(0, 256)
  const size = parsePageSize(input.size)
  if (size !== undefined) result.size = size
  if (typeof input.after === 'string' && input.after) result.after = input.after
  else if (typeof input.before === 'string' && input.before) {
    result.before = input.before
  }
  return result
}

export function userGroupsSearchKey(search: UserGroupsSearch): string {
  return JSON.stringify(normalizeUserGroupsSearch({ ...search }))
}

/** The filters a query is sent with: the form's values, trimmed. */
export function userGroupsAppliedFilters(
  search: UserGroupsSearch,
): UserGroupsFilters {
  return { q: search.q?.trim() || undefined }
}
