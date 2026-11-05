import { nextClientMutationId } from '#/lib/graphql/mutation-id'
import { useMemo } from 'react'

import {
  ConsoleAssignUserRolesDocument,
  ConsoleCreateRoleDocument,
  ConsoleDisableRoleDocument,
  ConsoleEnableRoleDocument,
  ConsoleRevokeUserRolesDocument,
  ConsoleSetRolePermissionsDocument,
  ConsoleUpdateRoleDocument,
  type AssignUserRolesInput,
  type ConsoleAssignUserRolesMutation,
  type ConsoleAssignUserRolesMutationVariables,
  type ConsoleCreateRoleMutation,
  type ConsoleCreateRoleMutationVariables,
  type ConsoleDisableRoleMutation,
  type ConsoleDisableRoleMutationVariables,
  type ConsoleEnableRoleMutation,
  type ConsoleEnableRoleMutationVariables,
  type ConsoleRevokeUserRolesMutation,
  type ConsoleRevokeUserRolesMutationVariables,
  type ConsoleSetRolePermissionsMutation,
  type ConsoleSetRolePermissionsMutationVariables,
  type ConsoleUpdateRoleMutation,
  type ConsoleUpdateRoleMutationVariables,
  type CreateRoleInput,
  type RevokeUserRolesInput,
  type RoleStateInput,
  type SetRolePermissionsInput,
  type UpdateRoleInput,
} from '#/generated/graphql'
import type { GraphQLResult } from '#/lib/graphql/transport'
import { useGraphQLMutation } from '#/lib/graphql/use-graphql-mutation'

export type RoleWriteResult =
  | GraphQLResult<ConsoleCreateRoleMutation>
  | GraphQLResult<ConsoleUpdateRoleMutation>
  | GraphQLResult<ConsoleEnableRoleMutation>
  | GraphQLResult<ConsoleDisableRoleMutation>
  | GraphQLResult<ConsoleSetRolePermissionsMutation>
  | GraphQLResult<ConsoleAssignUserRolesMutation>
  | GraphQLResult<ConsoleRevokeUserRolesMutation>

export function useRoleMutations() {
  const request = useGraphQLMutation()

  return useMemo(
    () => ({
      create(input: CreateRoleInput) {
        return request<
          ConsoleCreateRoleMutation,
          ConsoleCreateRoleMutationVariables
        >(
          ConsoleCreateRoleDocument,
          { input: { ...input, clientMutationId: nextClientMutationId() } },
          'ConsoleCreateRole',
        )
      },
      update(input: UpdateRoleInput) {
        return request<
          ConsoleUpdateRoleMutation,
          ConsoleUpdateRoleMutationVariables
        >(
          ConsoleUpdateRoleDocument,
          { input: { ...input, clientMutationId: nextClientMutationId() } },
          'ConsoleUpdateRole',
        )
      },
      enable(input: RoleStateInput) {
        return request<
          ConsoleEnableRoleMutation,
          ConsoleEnableRoleMutationVariables
        >(
          ConsoleEnableRoleDocument,
          { input: { ...input, clientMutationId: nextClientMutationId() } },
          'ConsoleEnableRole',
        )
      },
      disable(input: RoleStateInput) {
        return request<
          ConsoleDisableRoleMutation,
          ConsoleDisableRoleMutationVariables
        >(
          ConsoleDisableRoleDocument,
          { input: { ...input, clientMutationId: nextClientMutationId() } },
          'ConsoleDisableRole',
        )
      },
      setPermissions(input: SetRolePermissionsInput) {
        return request<
          ConsoleSetRolePermissionsMutation,
          ConsoleSetRolePermissionsMutationVariables
        >(
          ConsoleSetRolePermissionsDocument,
          { input: { ...input, clientMutationId: nextClientMutationId() } },
          'ConsoleSetRolePermissions',
        )
      },
      assignUserRoles(input: AssignUserRolesInput) {
        return request<
          ConsoleAssignUserRolesMutation,
          ConsoleAssignUserRolesMutationVariables
        >(
          ConsoleAssignUserRolesDocument,
          { input: { ...input, clientMutationId: nextClientMutationId() } },
          'ConsoleAssignUserRoles',
        )
      },
      revokeUserRoles(input: RevokeUserRolesInput) {
        return request<
          ConsoleRevokeUserRolesMutation,
          ConsoleRevokeUserRolesMutationVariables
        >(
          ConsoleRevokeUserRolesDocument,
          { input: { ...input, clientMutationId: nextClientMutationId() } },
          'ConsoleRevokeUserRoles',
        )
      },
    }),
    [request],
  )
}
