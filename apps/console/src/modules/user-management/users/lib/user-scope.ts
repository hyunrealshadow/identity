import { fieldAffordance } from '#/lib/graphql/affordances'
import type { EffectivePermissions } from '#/lib/workspace'

export function userManagementScope(
  permissions: EffectivePermissions | null | undefined,
) {
  const read = fieldAffordance(permissions, 'query', 'users')
  const create = fieldAffordance(permissions, 'mutation', 'createUser')
  const update = fieldAffordance(permissions, 'mutation', 'updateUser')
  const state = fieldAffordance(permissions, 'mutation', 'disableUser')
  const canWrite = create || update || state
  return { read, create, update, state, canWrite, hasAny: read || canWrite }
}

export type UserManagementScope = ReturnType<typeof userManagementScope>

/** `sub` is usually the same Global ID; tolerate an unqualified subject. */
export function isCurrentUser(
  userId: string,
  subject: string | undefined,
): boolean {
  if (!subject) return false
  if (userId === subject) return true
  const separator = Math.max(userId.lastIndexOf(':'), userId.lastIndexOf('/'))
  return separator >= 0 && userId.slice(separator + 1) === subject
}
