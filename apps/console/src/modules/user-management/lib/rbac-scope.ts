import type { EffectivePermissions } from '#/lib/workspace'

/**
 * Scope names are the GraphQL contract's management guards. The UI uses them
 * only to decide which bounded reads and affordances to offer; every backend
 * field remains authoritative.
 */
export const RBAC_SCOPES = {
  rolesRead: 'management.role.read',
  rolesWrite: 'management.role.write',
  permissionRead: 'management.scope.read',
  permissionWrite: 'management.scope.write',
  permissionDelegate: 'management.permission.delegate',
  scopesRead: 'management.scope.read',
  resourcesRead: 'management.resource.read',
  assignmentsRead: 'management.role_assignment.read',
  assignmentsWrite: 'management.role_assignment.write',
  usersRead: 'management.user.read',
  groupsRead: 'management.group.read',
  groupsWrite: 'management.group.write',
  groupMembershipsRead: 'management.group_membership.read',
  groupMembershipsWrite: 'management.group_membership.write',
  groupRolesRead: 'management.group_role.read',
  groupRolesWrite: 'management.group_role.write',
} as const

export interface RbacScope {
  rolesRead: boolean
  rolesWrite: boolean
  permissionRead: boolean
  permissionWrite: boolean
  permissionWriteReady: boolean
  permissionWriteStepUp: boolean
  permissionReadStepUp: boolean
  permissionDelegate: boolean
  scopesRead: boolean
  resourcesRead: boolean
  resourcesReadStepUp: boolean
  assignmentsRead: boolean
  assignmentsWrite: boolean
  usersRead: boolean
  groupsRead: boolean
  groupsWrite: boolean
  groupMembershipsRead: boolean
  groupMembershipsWrite: boolean
  groupRolesRead: boolean
  groupRolesWrite: boolean
  strongAuth: boolean
  roleWriteReady: boolean
  assignmentWriteReady: boolean
  groupsWriteReady: boolean
  groupMembershipsWriteReady: boolean
  groupRolesWriteReady: boolean
  roleWriteStepUp: boolean
  assignmentWriteStepUp: boolean
  groupsWriteStepUp: boolean
  groupMembershipsWriteStepUp: boolean
  groupRolesWriteStepUp: boolean
  roleReadStepUp: boolean
  assignmentReadStepUp: boolean
  usersReadStepUp: boolean
  groupsReadStepUp: boolean
  groupMembershipsReadStepUp: boolean
  groupRolesReadStepUp: boolean
  hasAny: boolean
}

const EMPTY_SCOPE: RbacScope = {
  rolesRead: false,
  rolesWrite: false,
  permissionRead: false,
  permissionWrite: false,
  permissionWriteReady: false,
  permissionWriteStepUp: false,
  permissionReadStepUp: false,
  permissionDelegate: false,
  scopesRead: false,
  resourcesRead: false,
  resourcesReadStepUp: false,
  assignmentsRead: false,
  assignmentsWrite: false,
  usersRead: false,
  groupsRead: false,
  groupsWrite: false,
  groupMembershipsRead: false,
  groupMembershipsWrite: false,
  groupRolesRead: false,
  groupRolesWrite: false,
  strongAuth: false,
  roleWriteReady: false,
  assignmentWriteReady: false,
  groupsWriteReady: false,
  groupMembershipsWriteReady: false,
  groupRolesWriteReady: false,
  roleWriteStepUp: false,
  assignmentWriteStepUp: false,
  groupsWriteStepUp: false,
  groupMembershipsWriteStepUp: false,
  groupRolesWriteStepUp: false,
  roleReadStepUp: false,
  assignmentReadStepUp: false,
  usersReadStepUp: false,
  groupsReadStepUp: false,
  groupMembershipsReadStepUp: false,
  groupRolesReadStepUp: false,
  hasAny: false,
}

export function rbacScope(
  permissions: EffectivePermissions | null | undefined,
): RbacScope {
  if (!permissions) return EMPTY_SCOPE

  const effective = new Set(permissions.effectiveScopes)
  const rolesRead = effective.has(RBAC_SCOPES.rolesRead)
  const rolesWrite = effective.has(RBAC_SCOPES.rolesWrite)
  const permissionRead = effective.has(RBAC_SCOPES.permissionRead)
  const permissionWrite = effective.has(RBAC_SCOPES.permissionWrite)
  const permissionDelegate = effective.has(RBAC_SCOPES.permissionDelegate)
  const scopesRead = effective.has(RBAC_SCOPES.scopesRead)
  const resourcesRead = effective.has(RBAC_SCOPES.resourcesRead)
  const assignmentsRead = effective.has(RBAC_SCOPES.assignmentsRead)
  const assignmentsWrite = effective.has(RBAC_SCOPES.assignmentsWrite)
  const usersRead = effective.has(RBAC_SCOPES.usersRead)
  const groupsRead = effective.has(RBAC_SCOPES.groupsRead)
  const groupsWrite = effective.has(RBAC_SCOPES.groupsWrite)
  const groupMembershipsRead = effective.has(RBAC_SCOPES.groupMembershipsRead)
  const groupMembershipsWrite = effective.has(RBAC_SCOPES.groupMembershipsWrite)
  const groupRolesRead = effective.has(RBAC_SCOPES.groupRolesRead)
  const groupRolesWrite = effective.has(RBAC_SCOPES.groupRolesWrite)
  const authentication = permissions.authentication
  const strongAuth =
    authentication.aal2 === true && authentication.recent === true
  const canStepUp = !strongAuth
  const requestable = new Set(permissions.requestableScopes)
  const roleWriteReady = rolesWrite && strongAuth
  const permissionWriteReady = permissionWrite && strongAuth
  const assignmentWriteReady = assignmentsWrite && strongAuth
  const groupsWriteReady = groupsWrite && strongAuth
  const groupMembershipsWriteReady = groupMembershipsWrite && strongAuth
  const groupRolesWriteReady = groupRolesWrite && strongAuth

  return {
    rolesRead,
    rolesWrite,
    permissionRead,
    permissionWrite,
    permissionWriteReady,
    permissionWriteStepUp:
      canStepUp &&
      !permissionWriteReady &&
      requestable.has(RBAC_SCOPES.permissionWrite),
    permissionReadStepUp:
      canStepUp &&
      !permissionRead &&
      requestable.has(RBAC_SCOPES.permissionRead),
    permissionDelegate,
    scopesRead,
    resourcesRead,
    resourcesReadStepUp:
      canStepUp && !resourcesRead && requestable.has(RBAC_SCOPES.resourcesRead),
    assignmentsRead,
    assignmentsWrite,
    usersRead,
    groupsRead,
    groupsWrite,
    groupMembershipsRead,
    groupMembershipsWrite,
    groupRolesRead,
    groupRolesWrite,
    strongAuth,
    roleWriteReady,
    assignmentWriteReady,
    groupsWriteReady,
    groupMembershipsWriteReady,
    groupRolesWriteReady,
    roleWriteStepUp:
      canStepUp && !roleWriteReady && requestable.has(RBAC_SCOPES.rolesWrite),
    assignmentWriteStepUp:
      canStepUp &&
      !assignmentWriteReady &&
      requestable.has(RBAC_SCOPES.assignmentsWrite),
    groupsWriteStepUp:
      canStepUp &&
      !groupsWriteReady &&
      requestable.has(RBAC_SCOPES.groupsWrite),
    groupMembershipsWriteStepUp:
      canStepUp &&
      !groupMembershipsWriteReady &&
      requestable.has(RBAC_SCOPES.groupMembershipsWrite),
    groupRolesWriteStepUp:
      canStepUp &&
      !groupRolesWriteReady &&
      requestable.has(RBAC_SCOPES.groupRolesWrite),
    roleReadStepUp:
      canStepUp && !rolesRead && requestable.has(RBAC_SCOPES.rolesRead),
    assignmentReadStepUp:
      canStepUp &&
      !assignmentsRead &&
      requestable.has(RBAC_SCOPES.assignmentsRead),
    usersReadStepUp:
      canStepUp && !usersRead && requestable.has(RBAC_SCOPES.usersRead),
    groupsReadStepUp:
      canStepUp && !groupsRead && requestable.has(RBAC_SCOPES.groupsRead),
    groupMembershipsReadStepUp:
      canStepUp &&
      !groupMembershipsRead &&
      requestable.has(RBAC_SCOPES.groupMembershipsRead),
    groupRolesReadStepUp:
      canStepUp &&
      !groupRolesRead &&
      requestable.has(RBAC_SCOPES.groupRolesRead),
    hasAny:
      rolesRead ||
      rolesWrite ||
      permissionRead ||
      permissionWrite ||
      permissionDelegate ||
      assignmentsRead ||
      assignmentsWrite ||
      usersRead ||
      groupsRead ||
      groupsWrite ||
      groupMembershipsRead ||
      groupMembershipsWrite ||
      groupRolesRead ||
      groupRolesWrite,
  }
}
