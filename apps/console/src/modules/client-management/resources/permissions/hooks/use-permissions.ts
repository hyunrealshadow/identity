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
} from '#/generated/graphql'
import { useConsoleQuery } from '#/lib/graphql/use-console-query'

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
    enabled,
    'missing_permission_connection',
    {
        keepPreviousData: (previous, next) =>
          previous.filter?.resourceId === next.filter?.resourceId,
      },
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
    enabled,
    'missing_scope_connection',
  )
}
