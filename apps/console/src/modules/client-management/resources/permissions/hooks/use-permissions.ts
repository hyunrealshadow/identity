import {
  ConsolePermissionDocument,
  ConsoleResourcePermissionsDocument,
  ConsoleScopesDocument,
  type ConsolePermissionQuery,
  type ConsolePermissionQueryVariables,
  type ConsoleResourcePermissionsQuery,
  type ConsoleResourcePermissionsQueryVariables,
  type ConsoleScopesQuery,
  type ConsoleScopesQueryVariables,
} from '#/gql/graphql'
import { useConsoleQuery } from '#/modules/user-management/lib/console-query'

export function usePermissionList(
  variables: ConsoleResourcePermissionsQueryVariables | null,
  enabled: boolean,
) {
  return useConsoleQuery<
    ConsoleResourcePermissionsQuery,
    ConsoleResourcePermissionsQueryVariables
  >(
    ConsoleResourcePermissionsDocument,
    variables,
    'ConsoleResourcePermissions',
    enabled,
    'missing_permission_connection',
  )
}

export function usePermissionDetail(
  permissionId: string,
  enabled: boolean,
  includeResource: boolean,
) {
  return useConsoleQuery<
    ConsolePermissionQuery,
    ConsolePermissionQueryVariables
  >(
    ConsolePermissionDocument,
    enabled ? { id: permissionId, includeResource } : null,
    'ConsolePermission',
    enabled,
    'missing_permission',
  )
}

export function useScopeOptions(
  variables: ConsoleScopesQueryVariables | null,
  enabled: boolean,
) {
  return useConsoleQuery<ConsoleScopesQuery, ConsoleScopesQueryVariables>(
    ConsoleScopesDocument,
    variables,
    'ConsoleScopes',
    enabled,
    'missing_scope_connection',
  )
}
