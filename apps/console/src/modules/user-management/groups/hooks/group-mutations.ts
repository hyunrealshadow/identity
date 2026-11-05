import { nextClientMutationId } from '#/lib/graphql/mutation-id'
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
} from '#/generated/graphql'
import type { GraphQLResult } from '#/lib/graphql/transport'
import { useGraphQLMutation } from '#/lib/graphql/use-graphql-mutation'

export type GroupWriteResult =
  | GraphQLResult<ConsoleCreateGroupMutation>
  | GraphQLResult<ConsoleUpdateGroupMutation>
  | GraphQLResult<ConsoleSetGroupEnabledMutation>
  | GraphQLResult<ConsoleDeleteGroupMutation>

export function useGroupMutations() {
  const request = useGraphQLMutation()

  return useMemo(
    () => ({
      create(input: CreateGroupInput) {
        return request<
          ConsoleCreateGroupMutation,
          ConsoleCreateGroupMutationVariables
        >(
          ConsoleCreateGroupDocument,
          { input: { ...input, clientMutationId: nextClientMutationId() } },
          'ConsoleCreateGroup',
        )
      },
      update(input: UpdateGroupInput) {
        return request<
          ConsoleUpdateGroupMutation,
          ConsoleUpdateGroupMutationVariables
        >(
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
        return request<
          ConsoleDeleteGroupMutation,
          ConsoleDeleteGroupMutationVariables
        >(
          ConsoleDeleteGroupDocument,
          { input: { ...input, clientMutationId: nextClientMutationId() } },
          'ConsoleDeleteGroup',
        )
      },
    }),
    [request],
  )
}
