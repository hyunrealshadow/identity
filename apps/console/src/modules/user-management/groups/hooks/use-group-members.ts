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
} from '#/gql/graphql'
import type { GraphQLResult } from '#/lib/graphql/transport'
import { useGraphQL } from '#/lib/graphql/use-graphql'
import { useConsoleQuery } from '#/modules/user-management/lib/console-query'

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

/**
 * Membership reads are bounded by the group query and the membership
 * connection guard. Passing null disables the request entirely.
 */
export function useGroupMembers(
  variables: ConsoleGroupMembersQueryVariables | null,
) {
  return useConsoleQuery<ConsoleGroupMembersQuery, ConsoleGroupMembersQueryVariables>(
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
  const request = useGraphQL()

  return useMemo(
    () => ({
      add(input: AddGroupMemberInput) {
        return request<
          ConsoleAddGroupMemberMutation,
          ConsoleAddGroupMemberMutationVariables
        >(
          ConsoleAddGroupMemberDocument,
          { input: { ...input, clientMutationId: nextClientMutationId() } },
          'ConsoleAddGroupMember',
        )
      },
      remove(input: RemoveGroupMemberInput) {
        return request<
          ConsoleRemoveGroupMemberMutation,
          ConsoleRemoveGroupMemberMutationVariables
        >(
          ConsoleRemoveGroupMemberDocument,
          { input: { ...input, clientMutationId: nextClientMutationId() } },
          'ConsoleRemoveGroupMember',
        )
      },
    }),
    [request],
  )
}
