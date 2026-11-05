import { nextClientMutationId } from '#/lib/graphql/mutation-id'
import { useMemo } from 'react'

import {
  ConsoleAddGroupMemberDocument,
  ConsoleGroupMembersDocument,
  ConsoleRemoveGroupMemberDocument,
  type AddGroupMemberInput,
  type ConsoleAddGroupMemberMutation,
  type ConsoleAddGroupMemberMutationVariables,
  type ConsoleGroupMembersQuery,
  type ConsoleGroupMembersQueryVariables,
  type ConsoleRemoveGroupMemberMutation,
  type ConsoleRemoveGroupMemberMutationVariables,
  type RemoveGroupMemberInput,
} from '#/generated/graphql'
import type { GraphQLResult } from '#/lib/graphql/transport'
import { useGraphQLMutation } from '#/lib/graphql/use-graphql-mutation'
import { useConsoleQuery } from '#/lib/graphql/use-console-query'

/**
 * Membership reads are bounded by the group query and the membership
 * connection guard. Passing null disables the request entirely.
 */
export function useGroupMembers(
  variables: ConsoleGroupMembersQueryVariables | null,
) {
  return useConsoleQuery<
    ConsoleGroupMembersQuery,
    ConsoleGroupMembersQueryVariables
  >(
    ConsoleGroupMembersDocument,
    variables,
    'ConsoleGroupMembers',
    Boolean(variables),
    'missing_group_members',
  )
}

export type GroupMemberWriteResult =
  | GraphQLResult<ConsoleAddGroupMemberMutation>
  | GraphQLResult<ConsoleRemoveGroupMemberMutation>

export function useGroupMemberMutations() {
  const request = useGraphQLMutation()

  return useMemo(
    () => ({
      add(input: AddGroupMemberInput) {
        return request<
          ConsoleAddGroupMemberMutation,
          ConsoleAddGroupMemberMutationVariables
        >(
          ConsoleAddGroupMemberDocument,
          { input: { ...input, clientMutationId: nextClientMutationId() } },
          'ConsoleAddGroupMember', ['ConsoleGroupMembers', 'ConsoleGroup'],
        )
      },
      remove(input: RemoveGroupMemberInput) {
        return request<
          ConsoleRemoveGroupMemberMutation,
          ConsoleRemoveGroupMemberMutationVariables
        >(
          ConsoleRemoveGroupMemberDocument,
          { input: { ...input, clientMutationId: nextClientMutationId() } },
          'ConsoleRemoveGroupMember', ['ConsoleGroupMembers', 'ConsoleGroup'],
        )
      },
    }),
    [request],
  )
}
