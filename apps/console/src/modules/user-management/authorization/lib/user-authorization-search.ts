import type { AuthorizationSourceFilterValue } from '#/modules/user-management/authorization/components/authorization-source-filter'
import {
  normalizeRelationPaging,
  searchOption,
  type RelationPagingSearch,
} from '#/modules/user-management/lib/relation-search'

export type UserRoleAssignmentStatus = 'any' | 'active' | 'revoked'
export const DEFAULT_USER_ROLE_STATUS: UserRoleAssignmentStatus = 'active'

const SOURCES: ReadonlyArray<AuthorizationSourceFilterValue> = [
  'any',
  'DIRECT',
  'GROUP',
]

/** URL search of a user's role assignments. */
export interface UserRolesSearch extends RelationPagingSearch {
  status?: UserRoleAssignmentStatus
  source?: AuthorizationSourceFilterValue
}

/** URL search of a user's effective permissions for one API resource. */
export interface UserPermissionsSearch extends RelationPagingSearch {
  resource?: string
  source?: AuthorizationSourceFilterValue
}

export function normalizeUserRolesSearch(
  input: Record<string, unknown>,
): UserRolesSearch {
  return {
    status: searchOption(
      input.status,
      ['any', 'active', 'revoked'],
      DEFAULT_USER_ROLE_STATUS,
    ),
    source: searchOption(input.source, SOURCES, 'any'),
    ...normalizeRelationPaging(input),
  }
}

export function normalizeUserPermissionsSearch(
  input: Record<string, unknown>,
): UserPermissionsSearch {
  return {
    resource:
      typeof input.resource === 'string' && input.resource
        ? input.resource
        : undefined,
    source: searchOption(input.source, SOURCES, 'any'),
    ...normalizeRelationPaging(input),
  }
}
