import { useQueryClient } from '@tanstack/react-query'
import { useCallback } from 'react'

import { useSessionVersion } from '#/lib/auth/session-version'
import type { GraphQLResult } from '#/lib/graphql/transport'
import { useLocale } from '#/lib/i18n'

interface EntityTarget {
  kind: 'entity'
  operation: string
  entity: string
  idField: string
  versionField: string
  /** New state for enable/disable payloads, which do not carry the flag. */
  enabled?: boolean
}

interface UserRolesTarget {
  kind: 'userRoles'
  operation: string
  idField: string
  versionField: string
}

type VersionTarget = EntityTarget | UserRolesTarget

function entity(
  operation: string,
  name: string,
  idField: string,
  versionField = 'version',
  enabled?: boolean,
): EntityTarget {
  return {
    kind: 'entity',
    operation,
    entity: name,
    idField,
    versionField,
    ...(enabled === undefined ? {} : { enabled }),
  }
}

function userRoles(operation: string): UserRolesTarget {
  return { kind: 'userRoles', operation, idField: 'userId', versionField: 'userVersion' }
}

const GROUP_TARGETS = [
  entity('ConsoleGroup', 'group', 'groupId'),
  entity('ConsoleGroupMembers', 'group', 'groupId'),
  entity('ConsoleGroupRoles', 'group', 'groupId'),
]

const GROUP_VERSION_TARGETS = [
  entity('ConsoleGroup', 'group', 'groupId', 'groupVersion'),
  entity('ConsoleGroupMembers', 'group', 'groupId', 'groupVersion'),
  entity('ConsoleGroupRoles', 'group', 'groupId', 'groupVersion'),
]

/**
 * Mutation payloads that carry the new optimistic-lock version of a resource.
 * The field name is the lower-cased operation without its `Console` prefix, so
 * each entry stays a single declaration.
 */
const VERSION_TARGETS: Record<string, readonly VersionTarget[]> = {
  ConsoleUpdateUser: [entity('ConsoleUser', 'user', 'userId')],
  ConsoleEnableUser: [entity('ConsoleUser', 'user', 'userId', 'version', true)],
  ConsoleDisableUser: [entity('ConsoleUser', 'user', 'userId', 'version', false)],
  ConsoleUnlockUser: [entity('ConsoleUser', 'user', 'userId')],

  ConsoleUpdateClient: [entity('ConsoleClient', 'client', 'clientId')],
  ConsoleEnableClient: [entity('ConsoleClient', 'client', 'clientId', 'version', true)],
  ConsoleDisableClient: [entity('ConsoleClient', 'client', 'clientId', 'version', false)],
  ConsoleCreateClientSecret: [entity('ConsoleClient', 'client', 'clientId')],
  ConsoleRotateClientSecret: [entity('ConsoleClient', 'client', 'clientId')],
  ConsoleRevokeClientCredential: [entity('ConsoleClient', 'client', 'clientId')],
  ConsoleSetClientScopes: [entity('ConsoleClient', 'client', 'clientId')],

  ConsoleUpdateGroup: GROUP_TARGETS,
  ConsoleSetGroupEnabled: GROUP_TARGETS,
  ConsoleAddGroupMember: GROUP_VERSION_TARGETS,
  ConsoleRemoveGroupMember: GROUP_VERSION_TARGETS,
  ConsoleSetGroupRoles: GROUP_VERSION_TARGETS,

  ConsoleUpdateRole: [entity('ConsoleRole', 'role', 'roleId')],
  ConsoleEnableRole: [entity('ConsoleRole', 'role', 'roleId', 'version', true)],
  ConsoleDisableRole: [entity('ConsoleRole', 'role', 'roleId', 'version', false)],
  ConsoleSetRolePermissions: [entity('ConsoleRole', 'role', 'roleId')],
  ConsoleAssignUserRoles: [userRoles('ConsoleUserRoles'), userRoles('ConsoleUserRoleVersion')],
  ConsoleRevokeUserRoles: [userRoles('ConsoleUserRoles'), userRoles('ConsoleUserRoleVersion')],

  ConsoleUpdatePermission: [entity('ConsolePermission', 'permission', 'scopeId')],
  ConsoleEnablePermission: [
    entity('ConsolePermission', 'permission', 'scopeId', 'version', true),
  ],
  ConsoleDisablePermission: [
    entity('ConsolePermission', 'permission', 'scopeId', 'version', false),
  ],
}

function payloadField(operation: string): string {
  const name = operation.startsWith('Console')
    ? operation.slice('Console'.length)
    : operation
  return name.charAt(0).toLowerCase() + name.slice(1)
}

function patchEntity(
  data: unknown,
  target: EntityTarget,
  id: string,
  version: string,
): unknown {
  const record = data as Record<string, unknown>
  const node = record[target.entity]
  if (!node || typeof node !== 'object') return data
  const entity = node as { id?: unknown; version?: unknown; enabled?: unknown }
  if (entity.id !== id) return data
  const enabledChanged =
    target.enabled !== undefined && entity.enabled !== target.enabled
  if (entity.version === version && !enabledChanged) return data
  return {
    ...record,
    [target.entity]: {
      ...entity,
      version,
      ...(target.enabled === undefined ? {} : { enabled: target.enabled }),
    },
  }
}

function patchUserRoles(
  data: unknown,
  id: string,
  version: string,
): unknown {
  const record = data as {
    user?: { id?: unknown; roles?: Record<string, unknown> }
  }
  const user = record.user
  if (!user || user.id !== id || !user.roles) return data
  if (user.roles.userVersion === version) return data
  return {
    ...record,
    user: { ...user, roles: { ...user.roles, userVersion: version } },
  }
}

/**
 * Applies the version returned by a write to the detail reads already cached
 * for that resource.
 *
 * The payloads expose only `id` and `version` (entity objects are separately
 * authorized), so this is a partial update, not a replacement: it keeps an
 * optimistic-lock version current while the invalidation refetch fills in the
 * remaining fields. Cached entries for another account or locale are never
 * touched because the key prefix includes both.
 */
export function usePatchVersionedEntities() {
  const client = useQueryClient()
  const sessionVersion = useSessionVersion()
  const { locale } = useLocale()

  return useCallback(
    (operationName: string | undefined, data: unknown) => {
      if (!operationName || !data) return
      const targets = VERSION_TARGETS[operationName]
      if (!targets) return
      const payload = (data as Record<string, unknown>)[payloadField(operationName)]
      if (!payload || typeof payload !== 'object') return

      for (const target of targets) {
        const id = (payload as Record<string, unknown>)[target.idField]
        const version = (payload as Record<string, unknown>)[target.versionField]
        if (typeof id !== 'string' || typeof version !== 'string') continue

        const queries = client.getQueryCache().findAll({
          queryKey: ['console', sessionVersion, locale, target.operation],
        })
        for (const query of queries) {
          const current = query.state.data as GraphQLResult<unknown> | undefined
          if (!current?.data) continue
          const next =
            target.kind === 'entity'
              ? patchEntity(current.data, target, id, version)
              : patchUserRoles(current.data, id, version)
          if (next === current.data) continue
          client.setQueryData(query.queryKey, { ...current, data: next })
        }
      }
    },
    [client, locale, sessionVersion],
  )
}
