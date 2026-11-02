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

function nextClientMutationId(): string {
  try {
    const value = globalThis.crypto?.randomUUID?.()
    if (value) return value
  } catch {
    // A blocked crypto implementation still gets a fresh opaque value.
  }
  return `console-${Date.now().toString(36)}-${Math.random()
    .toString(36)
    .slice(2, 10)}`
}

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
