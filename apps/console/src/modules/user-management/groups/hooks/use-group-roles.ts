import { nextClientMutationId } from '#/lib/graphql/mutation-id'
import { useMemo } from 'react'

import {
  ConsoleGroupDocument,
  ConsoleGroupRoleIdsDocument,
  ConsoleGroupRolesDocument,
  ConsoleSetGroupRolesDocument,
  ConsoleUserPermissionsDocument,
  ConsoleUserRolesDocument,
  type ConsoleGroupRoleIdsQuery,
  type ConsoleGroupRoleIdsQueryVariables,
  type ConsoleGroupRolesQuery,
  type ConsoleGroupRolesQueryVariables,
  type ConsoleSetGroupRolesMutation,
  type ConsoleSetGroupRolesMutationVariables,
  type SetGroupRolesInput,
} from '#/generated/graphql'
import type {
  GraphQLFailure,
  GraphQLIssue,
  GraphQLResult,
  GraphQLStepUp,
} from '#/lib/graphql/transport'
import { useGraphQL } from '#/lib/graphql/use-graphql'
import { useGraphQLMutation } from '#/lib/graphql/use-graphql-mutation'
import {
  sameVariable,
  useConsoleQuery,
} from '#/lib/graphql/use-console-query'

const ROLE_LINK_SCAN_SIZE = 25
const MAX_ROLE_LINK_PAGES = 40

export function useGroupRoles(
  variables: ConsoleGroupRolesQueryVariables | null,
) {
  return useConsoleQuery<
    ConsoleGroupRolesQuery,
    ConsoleGroupRolesQueryVariables
  >(
    ConsoleGroupRolesDocument,
    variables,
    Boolean(variables),
    'missing_group_roles',
    { keepPreviousData: sameVariable('groupId') },
  )
}

export interface GroupRoleLinkSnapshot {
  roleIds: string[]
  errors: GraphQLIssue[]
  failure?: GraphQLFailure
  requestId?: string
  traceId?: string
  stepUp?: GraphQLStepUp
  forbidden: boolean
  partial: boolean
}

/**
 * Loads the complete set of currently active role links before an explicit
 * replacement. setGroupRoles replaces the whole business role set, so a
 * bounded page alone would silently drop links the operator cannot see.
 */
export function useGroupRoleMutations() {
  const request = useGraphQL()
  const mutate = useGraphQLMutation()

  return useMemo(
    () => ({
      setRoles(input: SetGroupRolesInput) {
        return mutate<
          ConsoleSetGroupRolesMutation,
          ConsoleSetGroupRolesMutationVariables
        >(
          ConsoleSetGroupRolesDocument,
          { input: { ...input, clientMutationId: nextClientMutationId() } },
          [
            ConsoleGroupRolesDocument,
            ConsoleGroupRoleIdsDocument,
            ConsoleGroupDocument,
            ConsoleUserRolesDocument,
            ConsoleUserPermissionsDocument,
          ],
        )
      },
      async loadActiveRoleIds(groupId: string): Promise<GroupRoleLinkSnapshot> {
        const ids = new Set<string>()
        let after: string | undefined
        let requestId: string | undefined
        let traceId: string | undefined
        let partial = false

        for (let page = 0; page < MAX_ROLE_LINK_PAGES; page += 1) {
          const result: GraphQLResult<ConsoleGroupRoleIdsQuery> = await request<
            ConsoleGroupRoleIdsQuery,
            ConsoleGroupRoleIdsQueryVariables
          >(
            ConsoleGroupRoleIdsDocument,
            {
              groupId,
              first: ROLE_LINK_SCAN_SIZE,
              ...(after ? { after } : {}),
            },
            'ConsoleGroupRoleIds',
          )
          requestId = result.requestId ?? requestId
          traceId = result.traceId ?? traceId
          if (result.partial) partial = true
          const connection = result.data?.group?.roles ?? null
          if (!connection) {
            return {
              roleIds: [...ids],
              errors: result.errors,
              failure: result.failure ?? {
                kind: 'invalid_response',
                code: 'missing_group_role_snapshot',
                requestId: result.requestId,
                traceId: result.traceId,
              },
              requestId,
              traceId,
              stepUp: result.stepUp,
              forbidden: result.forbidden,
              partial,
            }
          }
          for (const edge of connection.edges) {
            if (edge.enabled && !edge.revokedAt) ids.add(edge.node.id)
          }
          if (!connection.pageInfo.hasNextPage) {
            return {
              roleIds: [...ids],
              errors: result.errors,
              requestId,
              traceId,
              forbidden: result.forbidden,
              partial,
            }
          }
          after = connection.pageInfo.endCursor ?? undefined
          if (!after) {
            return {
              roleIds: [...ids],
              errors: result.errors,
              failure: {
                kind: 'invalid_response',
                code: 'missing_group_role_cursor',
                requestId,
                traceId,
              },
              requestId,
              traceId,
              forbidden: result.forbidden,
              partial,
            }
          }
        }
        return {
          roleIds: [...ids],
          errors: [],
          failure: {
            kind: 'invalid_response',
            code: 'group_role_snapshot_limit',
            requestId,
            traceId,
          },
          requestId,
          traceId,
          forbidden: false,
          partial,
        }
      },
    }),
    [mutate, request],
  )
}
