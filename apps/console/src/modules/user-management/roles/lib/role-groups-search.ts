export type RoleGroupsKind = 'any' | 'builtin' | 'custom'
export type RoleGroupsOrder = 'CREATED_AT_ASC' | 'CREATED_AT_DESC'

/** URL search of a role's group list; it mirrors the filter form. */
export interface RoleGroupsSearch {
  q?: string
  kind?: Exclude<RoleGroupsKind, 'any'>
  order?: RoleGroupsOrder
  after?: string
  before?: string
}

export interface RoleGroupsFilterState {
  query: string
  kind: RoleGroupsKind
  order: RoleGroupsOrder
}

export const DEFAULT_ROLE_GROUPS_FILTER: RoleGroupsFilterState = {
  query: '',
  kind: 'any',
  order: 'CREATED_AT_DESC',
}

export function normalizeRoleGroupsSearch(
  input: Record<string, unknown>,
): RoleGroupsSearch {
  const result: RoleGroupsSearch = {}
  // Typed text stays as the form holds it; it is trimmed when applied.
  if (typeof input.q === 'string' && input.q) result.q = input.q.slice(0, 255)
  if (input.kind === 'builtin' || input.kind === 'custom') result.kind = input.kind
  if (input.order === 'CREATED_AT_ASC' || input.order === 'CREATED_AT_DESC') {
    result.order = input.order
  }
  if (typeof input.after === 'string' && input.after) result.after = input.after
  else if (typeof input.before === 'string' && input.before) {
    result.before = input.before
  }
  return result
}

export function roleGroupsSearchKey(search: RoleGroupsSearch): string {
  return JSON.stringify(normalizeRoleGroupsSearch({ ...search }))
}

/** The form's current values, read from the URL. */
export function roleGroupsFormState(
  search: RoleGroupsSearch,
): RoleGroupsFilterState {
  return {
    query: search.q ?? '',
    kind: search.kind ?? 'any',
    order: search.order ?? DEFAULT_ROLE_GROUPS_FILTER.order,
  }
}

/** The form as it is written to the URL, without normalising typed text. */
export function roleGroupsFormSearch(
  state: RoleGroupsFilterState,
): RoleGroupsSearch {
  return {
    q: state.query || undefined,
    kind: state.kind === 'any' ? undefined : state.kind,
    order:
      state.order === DEFAULT_ROLE_GROUPS_FILTER.order ? undefined : state.order,
  }
}

/** The filters a query is sent with: the form's values, trimmed. */
export function roleGroupsAppliedFilters(
  search: RoleGroupsSearch,
): RoleGroupsFilterState {
  const form = roleGroupsFormState(search)
  return { ...form, query: form.query.trim() }
}
