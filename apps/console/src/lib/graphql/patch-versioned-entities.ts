import { useQueryClient } from '@tanstack/react-query'
import { useCallback } from 'react'

import { useSessionVersion } from '#/lib/auth/session-version'
import type { GraphQLResult } from '#/lib/graphql/transport'
import {
  ConsoleAddGroupMemberDocument,
  ConsoleAssignUserRolesDocument,
  ConsoleClientDocument,
  ConsoleCreateClientSecretDocument,
  ConsoleDisableClientDocument,
  ConsoleDisablePermissionDocument,
  ConsoleDisableRoleDocument,
  ConsoleDisableUserDocument,
  ConsoleEnableClientDocument,
  ConsoleEnablePermissionDocument,
  ConsoleEnableRoleDocument,
  ConsoleEnableUserDocument,
  ConsoleGroupDocument,
  ConsoleGroupMembersDocument,
  ConsoleGroupRolesDocument,
  ConsolePermissionDocument,
  ConsoleRemoveGroupMemberDocument,
  ConsoleRevokeClientCredentialDocument,
  ConsoleRevokeUserRolesDocument,
  ConsoleRoleDocument,
  ConsoleRotateClientSecretDocument,
  ConsoleSetClientScopesDocument,
  ConsoleSetGroupEnabledDocument,
  ConsoleSetGroupRolesDocument,
  ConsoleSetRolePermissionsDocument,
  ConsoleUnlockUserDocument,
  ConsoleUpdateClientDocument,
  ConsoleUpdateGroupDocument,
  ConsoleUpdatePermissionDocument,
  ConsoleUpdateRoleDocument,
  ConsoleUpdateUserDocument,
  ConsoleUserDocument,
  ConsoleUserRolesDocument,
  ConsoleUserRoleVersionDocument,
} from '#/generated/graphql'
import { useLocale } from '#/lib/i18n'
import {
  consoleQueryKeys,
  operationNameOf,
  type AnyDocument,
} from './query-keys'

interface EntityTarget {
  kind: 'entity'
  read: AnyDocument
  entity: string
  idField: string
  versionField: string
  /** New state for enable/disable payloads, which do not carry the flag. */
  enabled?: boolean
}

interface UserRolesTarget {
  kind: 'userRoles'
  read: AnyDocument
  idField: string
  versionField: string
}

type VersionTarget = EntityTarget | UserRolesTarget

function entity(
  read: AnyDocument,
  name: string,
  idField: string,
  versionField = 'version',
): EntityTarget {
  return { kind: 'entity', read, entity: name, idField, versionField }
}

function userRoles(read: AnyDocument): UserRolesTarget {
  return { kind: 'userRoles', read, idField: 'userId', versionField: 'userVersion' }
}

const GROUP_TARGETS = [
  entity(ConsoleGroupDocument, 'group', 'groupId'),
  entity(ConsoleGroupMembersDocument, 'group', 'groupId'),
  entity(ConsoleGroupRolesDocument, 'group', 'groupId'),
]

const GROUP_VERSION_TARGETS = [
  entity(ConsoleGroupDocument, 'group', 'groupId', 'groupVersion'),
  entity(ConsoleGroupMembersDocument, 'group', 'groupId', 'groupVersion'),
  entity(ConsoleGroupRolesDocument, 'group', 'groupId', 'groupVersion'),
]

const USER = entity(ConsoleUserDocument, 'user', 'userId')
const CLIENT = entity(ConsoleClientDocument, 'client', 'clientId')
const ROLE = entity(ConsoleRoleDocument, 'role', 'roleId')
const PERMISSION = entity(ConsolePermissionDocument, 'permission', 'scopeId')
const USER_ROLES = [
  userRoles(ConsoleUserRolesDocument),
  userRoles(ConsoleUserRoleVersionDocument),
]

/** The same entity target, carrying the state an enable/disable sets. */
function withEnabled(target: EntityTarget, enabled: boolean): EntityTarget {
  return { ...target, enabled }
}

/**
 * Mutation payloads that carry the new optimistic-lock version of a resource,
 * keyed by mutation document. The payload field is the lower-cased operation
 * without its `Console` prefix, so each entry stays a single declaration.
 */
const VERSION_TARGETS = new Map<string, readonly VersionTarget[]>(
  (
    [
      [ConsoleUpdateUserDocument, [USER]],
      [ConsoleEnableUserDocument, [withEnabled(USER, true)]],
      [ConsoleDisableUserDocument, [withEnabled(USER, false)]],
      [ConsoleUnlockUserDocument, [USER]],

      [ConsoleUpdateClientDocument, [CLIENT]],
      [ConsoleEnableClientDocument, [withEnabled(CLIENT, true)]],
      [ConsoleDisableClientDocument, [withEnabled(CLIENT, false)]],
      [ConsoleCreateClientSecretDocument, [CLIENT]],
      [ConsoleRotateClientSecretDocument, [CLIENT]],
      [ConsoleRevokeClientCredentialDocument, [CLIENT]],
      [ConsoleSetClientScopesDocument, [CLIENT]],

      [ConsoleUpdateGroupDocument, GROUP_TARGETS],
      [ConsoleSetGroupEnabledDocument, GROUP_TARGETS],
      [ConsoleAddGroupMemberDocument, GROUP_VERSION_TARGETS],
      [ConsoleRemoveGroupMemberDocument, GROUP_VERSION_TARGETS],
      [ConsoleSetGroupRolesDocument, GROUP_VERSION_TARGETS],

      [ConsoleUpdateRoleDocument, [ROLE]],
      [ConsoleEnableRoleDocument, [withEnabled(ROLE, true)]],
      [ConsoleDisableRoleDocument, [withEnabled(ROLE, false)]],
      [ConsoleSetRolePermissionsDocument, [ROLE]],
      [ConsoleAssignUserRolesDocument, USER_ROLES],
      [ConsoleRevokeUserRolesDocument, USER_ROLES],

      [ConsoleUpdatePermissionDocument, [PERMISSION]],
      [ConsoleEnablePermissionDocument, [withEnabled(PERMISSION, true)]],
      [ConsoleDisablePermissionDocument, [withEnabled(PERMISSION, false)]],
    ] as const satisfies ReadonlyArray<readonly [AnyDocument, readonly VersionTarget[]]>
  ).map(([document, targets]) => [operationNameOf(document), targets]),
)

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
    (mutation: AnyDocument, data: unknown) => {
      if (!data) return
      const operationName = operationNameOf(mutation)
      const targets = VERSION_TARGETS.get(operationName)
      if (!targets) return
      const payload = (data as Record<string, unknown>)[payloadField(operationName)]
      if (!payload || typeof payload !== 'object') return

      for (const target of targets) {
        const id = (payload as Record<string, unknown>)[target.idField]
        const version = (payload as Record<string, unknown>)[target.versionField]
        if (typeof id !== 'string' || typeof version !== 'string') continue

        const queries = client.getQueryCache().findAll({
          queryKey: consoleQueryKeys.operation(sessionVersion, locale, target.read),
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
