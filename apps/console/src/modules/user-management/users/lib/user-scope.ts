import type { EffectivePermissions } from '#/lib/workspace'

export const USER_MANAGEMENT_SCOPES = {
  read: 'management.user.read',
  create: 'management.user.create',
  update: 'management.user.update',
  state: 'management.user.state',
} as const

const WRITE_SCOPES = [
  USER_MANAGEMENT_SCOPES.create,
  USER_MANAGEMENT_SCOPES.update,
  USER_MANAGEMENT_SCOPES.state,
] as const

export interface UserManagementScope {
  read: boolean
  create: boolean
  update: boolean
  state: boolean
  canWrite: boolean
  hasAny: boolean
  /** No effective user scope, but stronger authentication could unlock one. */
  readStepUp: boolean
  /** Read access exists, but write scopes might appear after stronger authentication. */
  writeStepUp: boolean
}

const EMPTY_SCOPE: UserManagementScope = {
  read: false,
  create: false,
  update: false,
  state: false,
  canWrite: false,
  hasAny: false,
  readStepUp: false,
  writeStepUp: false,
}

/**
 * Derive local user-management affordances from the bootstrap snapshot. The
 * backend remains authoritative for every read and write.
 */
export function userManagementScope(
  permissions: EffectivePermissions | null | undefined,
): UserManagementScope {
  if (!permissions) return EMPTY_SCOPE

  const effective = new Set(permissions.effectiveScopes)
  const read = effective.has(USER_MANAGEMENT_SCOPES.read)
  const create = effective.has(USER_MANAGEMENT_SCOPES.create)
  const update = effective.has(USER_MANAGEMENT_SCOPES.update)
  const state = effective.has(USER_MANAGEMENT_SCOPES.state)
  const canWrite = create || update || state
  const hasAny = read || canWrite

  const authentication = permissions.authentication
  const canStepUp = authentication?.aal2 !== true
  const canRefreshAuthentication = canStepUp || authentication?.recent !== true
  const requestable = new Set(permissions.requestableScopes)

  const readStepUp =
    !read && canStepUp && requestable.has(USER_MANAGEMENT_SCOPES.read)
  const writeStepUp =
    read &&
    !canWrite &&
    canRefreshAuthentication &&
    WRITE_SCOPES.some((scope) => requestable.has(scope))

  return {
    read,
    create,
    update,
    state,
    canWrite,
    hasAny,
    readStepUp,
    writeStepUp,
  }
}

/** `sub` is usually the same Global ID; tolerate an unqualified subject. */
export function isCurrentUser(userId: string, subject: string | undefined): boolean {
  if (!subject) return false
  if (userId === subject) return true
  const separator = Math.max(userId.lastIndexOf(':'), userId.lastIndexOf('/'))
  return separator >= 0 && userId.slice(separator + 1) === subject
}
