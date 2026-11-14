import {
  normalizeRelationPaging,
  searchOption,
  searchText,
  type RelationPagingSearch,
} from '#/modules/user-management/lib/relation-search'

export type GroupRelationStatus = 'any' | 'enabled' | 'disabled'
const STATUSES: ReadonlyArray<GroupRelationStatus> = ['any', 'enabled', 'disabled']

/** URL search of a group's member list. */
export interface GroupMembersSearch extends RelationPagingSearch {
  status?: GroupRelationStatus
}

/** URL search of a group's role list; `q` filters the loaded page. */
export interface GroupRolesSearch extends RelationPagingSearch {
  q?: string
  status?: GroupRelationStatus
}

export function normalizeGroupMembersSearch(
  input: Record<string, unknown>,
): GroupMembersSearch {
  return {
    status: searchOption(input.status, STATUSES, 'any'),
    ...normalizeRelationPaging(input),
  }
}

export function normalizeGroupRolesSearch(
  input: Record<string, unknown>,
): GroupRolesSearch {
  return {
    q: searchText(input.q),
    status: searchOption(input.status, STATUSES, 'any'),
    ...normalizeRelationPaging(input),
  }
}
