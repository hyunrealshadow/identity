import {
  normalizeRelationPaging,
  searchOption,
  type RelationPagingSearch,
} from '#/modules/user-management/lib/relation-search'

export type RoleUserStatus = 'any' | 'active' | 'revoked'

/** URL search of a role's user list. */
export interface RoleUsersSearch extends RelationPagingSearch {
  status?: RoleUserStatus
}

export function normalizeRoleUsersSearch(
  input: Record<string, unknown>,
): RoleUsersSearch {
  return {
    status: searchOption(input.status, ['any', 'active', 'revoked'], 'any'),
    ...normalizeRelationPaging(input),
  }
}
