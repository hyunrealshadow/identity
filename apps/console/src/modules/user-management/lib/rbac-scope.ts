import { fieldAffordance } from '#/lib/graphql/affordances'
import type { EffectivePermissions } from '#/lib/workspace'

/** UI affordances come from executable field declarations, never an authentication policy table. */
export function rbacScope(
  permissions: EffectivePermissions | null | undefined,
) {
  const query = (field: string) => fieldAffordance(permissions, 'query', field)
  const mutation = (field: string) =>
    fieldAffordance(permissions, 'mutation', field)
  return {
    rolesRead: query('roles'),
    rolesWrite: mutation('createRole'),
    permissionRead: query('scopes'),
    permissionWrite: mutation('createScope'),
    scopesRead: query('scopes'),
    resourcesRead: query('resources'),
    // Role assignments are read through user and role fields; this one needs
    // only the assignment read scope.
    assignmentsRead: fieldAffordance(permissions, 'User', 'effectivePermissions'),
    assignmentsWrite: mutation('assignUserRoles'),
    usersRead: query('users'),
    groupsRead: query('groups'),
    groupsWrite: mutation('createGroup'),
    groupMembershipsRead: fieldAffordance(permissions, 'Group', 'members'),
    groupMembershipsWrite: mutation('addGroupMember'),
    groupRolesRead: fieldAffordance(permissions, 'Group', 'roles'),
    groupRolesWrite: mutation('setGroupRoles'),
  }
}

export type RbacScope = ReturnType<typeof rbacScope>
