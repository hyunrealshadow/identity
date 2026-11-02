import { nextClientMutationId } from '#/lib/graphql/mutation-id'
import { useMemo } from 'react'

import {
  ConsoleCreatePermissionDocument,
  ConsoleDisablePermissionDocument,
  ConsoleEnablePermissionDocument,
  ConsoleUpdatePermissionDocument,
  type ConsoleCreatePermissionMutation,
  type ConsoleCreatePermissionMutationVariables,
  type ConsoleDisablePermissionMutation,
  type ConsoleDisablePermissionMutationVariables,
  type ConsoleEnablePermissionMutation,
  type ConsoleEnablePermissionMutationVariables,
  type ConsoleUpdatePermissionMutation,
  type ConsoleUpdatePermissionMutationVariables,
  type CreateScopeInput,
  type ScopeStateInput,
  type UpdateScopeInput,
} from '#/gql/graphql'
import type { GraphQLResult } from '#/lib/graphql/transport'
import { useGraphQL } from '#/lib/graphql/use-graphql'

export type PermissionWriteResult =
  | GraphQLResult<ConsoleCreatePermissionMutation>
  | GraphQLResult<ConsoleUpdatePermissionMutation>
  | GraphQLResult<ConsoleEnablePermissionMutation>
  | GraphQLResult<ConsoleDisablePermissionMutation>

export function usePermissionMutations() {
  const request = useGraphQL()

  return useMemo(
    () => ({
      create(input: CreateScopeInput) {
        return request<
          ConsoleCreatePermissionMutation,
          ConsoleCreatePermissionMutationVariables
        >(
          ConsoleCreatePermissionDocument,
          { input: { ...input, clientMutationId: nextClientMutationId() } },
          'ConsoleCreatePermission',
        )
      },
      update(input: UpdateScopeInput) {
        return request<
          ConsoleUpdatePermissionMutation,
          ConsoleUpdatePermissionMutationVariables
        >(
          ConsoleUpdatePermissionDocument,
          { input: { ...input, clientMutationId: nextClientMutationId() } },
          'ConsoleUpdatePermission',
        )
      },
      enable(input: ScopeStateInput) {
        return request<
          ConsoleEnablePermissionMutation,
          ConsoleEnablePermissionMutationVariables
        >(
          ConsoleEnablePermissionDocument,
          { input: { ...input, clientMutationId: nextClientMutationId() } },
          'ConsoleEnablePermission',
        )
      },
      disable(input: ScopeStateInput) {
        return request<
          ConsoleDisablePermissionMutation,
          ConsoleDisablePermissionMutationVariables
        >(
          ConsoleDisablePermissionDocument,
          { input: { ...input, clientMutationId: nextClientMutationId() } },
          'ConsoleDisablePermission',
        )
      },
    }),
    [request],
  )
}
