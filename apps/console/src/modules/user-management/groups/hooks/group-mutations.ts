import { useMemo } from 'react'

import {
  ConsoleCreateGroupDocument,
  ConsoleDeleteGroupDocument,
  ConsoleSetGroupEnabledDocument,
  ConsoleUpdateGroupDocument,
  type ConsoleCreateGroupMutation,
  type ConsoleCreateGroupMutationVariables,
  type ConsoleDeleteGroupMutation,
  type ConsoleDeleteGroupMutationVariables,
  type ConsoleSetGroupEnabledMutation,
  type ConsoleSetGroupEnabledMutationVariables,
  type ConsoleUpdateGroupMutation,
  type ConsoleUpdateGroupMutationVariables,
  type CreateGroupInput,
  type GroupStateInput,
  type SetGroupEnabledInput,
  type UpdateGroupInput,
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

export type GroupWriteResult =
  | GraphQLResult<ConsoleCreateGroupMutation>
  | GraphQLResult<ConsoleUpdateGroupMutation>
  | GraphQLResult<ConsoleSetGroupEnabledMutation>
  | GraphQLResult<ConsoleDeleteGroupMutation>

export function useGroupMutations() {
  const request = useGraphQL()

  return useMemo(
    () => ({
      create(input: CreateGroupInput) {
        return request<ConsoleCreateGroupMutation, ConsoleCreateGroupMutationVariables>(
          ConsoleCreateGroupDocument,
          { input: { ...input, clientMutationId: nextClientMutationId() } },
          'ConsoleCreateGroup',
        )
      },
      update(input: UpdateGroupInput) {
        return request<ConsoleUpdateGroupMutation, ConsoleUpdateGroupMutationVariables>(
          ConsoleUpdateGroupDocument,
          { input: { ...input, clientMutationId: nextClientMutationId() } },
          'ConsoleUpdateGroup',
        )
      },
      setEnabled(input: SetGroupEnabledInput) {
        return request<
          ConsoleSetGroupEnabledMutation,
          ConsoleSetGroupEnabledMutationVariables
        >(
          ConsoleSetGroupEnabledDocument,
          { input: { ...input, clientMutationId: nextClientMutationId() } },
          'ConsoleSetGroupEnabled',
        )
      },
      remove(input: GroupStateInput) {
        return request<ConsoleDeleteGroupMutation, ConsoleDeleteGroupMutationVariables>(
          ConsoleDeleteGroupDocument,
          { input: { ...input, clientMutationId: nextClientMutationId() } },
          'ConsoleDeleteGroup',
        )
      },
    }),
    [request],
  )
}
