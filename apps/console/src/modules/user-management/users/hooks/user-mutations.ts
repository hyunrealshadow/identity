import { nextClientMutationId } from '#/lib/graphql/mutation-id'
import { useMemo } from 'react'

import {
  ConsoleCreateUserDocument,
  ConsoleDisableUserDocument,
  ConsoleEnableUserDocument,
  ConsoleUnlockUserDocument,
  ConsoleUpdateUserDocument,
  ConsoleUserDocument,
  ConsoleUsersDocument,
  type ConsoleCreateUserMutation,
  type ConsoleCreateUserMutationVariables,
  type ConsoleDisableUserMutation,
  type ConsoleDisableUserMutationVariables,
  type ConsoleEnableUserMutation,
  type ConsoleEnableUserMutationVariables,
  type ConsoleUnlockUserMutation,
  type ConsoleUnlockUserMutationVariables,
  type ConsoleUpdateUserMutation,
  type ConsoleUpdateUserMutationVariables,
  type CreateUserInput,
  type UnlockUserInput,
  type UpdateUserInput,
  type UserStateInput,
} from '#/generated/graphql'
import type { GraphQLResult } from '#/lib/graphql/transport'
import { useGraphQLMutation } from '#/lib/graphql/use-graphql-mutation'

export type CreateUserPayload = NonNullable<
  ConsoleCreateUserMutation['createUser']
>
export type UpdateUserPayload = NonNullable<
  ConsoleUpdateUserMutation['updateUser']
>
export type EnableUserPayload = NonNullable<
  ConsoleEnableUserMutation['enableUser']
>
export type DisableUserPayload = NonNullable<
  ConsoleDisableUserMutation['disableUser']
>
export type UnlockUserPayload = NonNullable<
  ConsoleUnlockUserMutation['unlockUser']
>

export type CreateUserResult = GraphQLResult<ConsoleCreateUserMutation>
export type UpdateUserResult = GraphQLResult<ConsoleUpdateUserMutation>
export type StateUserResult =
  | GraphQLResult<ConsoleEnableUserMutation>
  | GraphQLResult<ConsoleDisableUserMutation>
  | GraphQLResult<ConsoleUnlockUserMutation>

export interface UserMutations {
  create: (input: CreateUserInput) => Promise<CreateUserResult>
  update: (input: UpdateUserInput) => Promise<UpdateUserResult>
  enable: (
    input: UserStateInput,
  ) => Promise<GraphQLResult<ConsoleEnableUserMutation>>
  disable: (
    input: UserStateInput,
  ) => Promise<GraphQLResult<ConsoleDisableUserMutation>>
  unlock: (
    input: UnlockUserInput,
  ) => Promise<GraphQLResult<ConsoleUnlockUserMutation>>
}

/**
 * Every sensitive submit gets a fresh client mutation id. Callers must not
 * replay a failed write automatically.
 */
export function useUserMutations(): UserMutations {
  const request = useGraphQLMutation()

  return useMemo(
    () => ({
      create(input) {
        const variables: ConsoleCreateUserMutationVariables = {
          input: { ...input, clientMutationId: nextClientMutationId() },
        }
        return request<
          ConsoleCreateUserMutation,
          ConsoleCreateUserMutationVariables
        >(ConsoleCreateUserDocument, variables, [ConsoleUsersDocument])
      },
      update(input) {
        const variables: ConsoleUpdateUserMutationVariables = {
          input: { ...input, clientMutationId: nextClientMutationId() },
        }
        return request<
          ConsoleUpdateUserMutation,
          ConsoleUpdateUserMutationVariables
        >(ConsoleUpdateUserDocument, variables, [ConsoleUserDocument, ConsoleUsersDocument])
      },
      enable(input) {
        const variables: ConsoleEnableUserMutationVariables = {
          input: { ...input, clientMutationId: nextClientMutationId() },
        }
        return request<
          ConsoleEnableUserMutation,
          ConsoleEnableUserMutationVariables
        >(ConsoleEnableUserDocument, variables, [ConsoleUserDocument, ConsoleUsersDocument])
      },
      disable(input) {
        const variables: ConsoleDisableUserMutationVariables = {
          input: { ...input, clientMutationId: nextClientMutationId() },
        }
        return request<
          ConsoleDisableUserMutation,
          ConsoleDisableUserMutationVariables
        >(ConsoleDisableUserDocument, variables, [ConsoleUserDocument, ConsoleUsersDocument])
      },
      unlock(input) {
        const variables: ConsoleUnlockUserMutationVariables = {
          input: { ...input, clientMutationId: nextClientMutationId() },
        }
        return request<
          ConsoleUnlockUserMutation,
          ConsoleUnlockUserMutationVariables
        >(ConsoleUnlockUserDocument, variables, [ConsoleUserDocument, ConsoleUsersDocument])
      },
    }),
    [request],
  )
}
