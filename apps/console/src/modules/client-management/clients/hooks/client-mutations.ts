import { useMemo } from 'react'

import {
  ConsoleCreateClientDocument,
  ConsoleCreateClientSecretDocument,
  ConsoleDeleteClientDocument,
  ConsoleDisableClientDocument,
  ConsoleEnableClientDocument,
  ConsoleRevokeClientCredentialDocument,
  ConsoleRotateClientSecretDocument,
  ConsoleSetClientScopesDocument,
  ConsoleUpdateClientDocument,
  type ClientStateInput,
  type ConsoleCreateClientMutation,
  type ConsoleCreateClientMutationVariables,
  type ConsoleCreateClientSecretMutation,
  type ConsoleCreateClientSecretMutationVariables,
  type ConsoleDeleteClientMutation,
  type ConsoleDeleteClientMutationVariables,
  type ConsoleDisableClientMutation,
  type ConsoleDisableClientMutationVariables,
  type ConsoleEnableClientMutation,
  type ConsoleEnableClientMutationVariables,
  type ConsoleRevokeClientCredentialMutation,
  type ConsoleRevokeClientCredentialMutationVariables,
  type ConsoleRotateClientSecretMutation,
  type ConsoleRotateClientSecretMutationVariables,
  type ConsoleSetClientScopesMutation,
  type ConsoleSetClientScopesMutationVariables,
  type ConsoleUpdateClientMutation,
  type ConsoleUpdateClientMutationVariables,
  type CreateClientInput,
  type CreateClientSecretInput,
  type RevokeClientCredentialInput,
  type RotateClientSecretInput,
  type SetClientScopesInput,
  type UpdateClientInput,
} from '#/gql/graphql'
import { nextClientMutationId } from '#/lib/graphql/mutation-id'
import { useGraphQL } from '#/lib/graphql/use-graphql'

export function useClientMutations() {
  const request = useGraphQL()
  return useMemo(
    () => ({
      create(input: CreateClientInput) {
        return request<ConsoleCreateClientMutation, ConsoleCreateClientMutationVariables>(
          ConsoleCreateClientDocument,
          { input: { ...input, clientMutationId: nextClientMutationId() } },
          'ConsoleCreateClient',
        )
      },
      update(input: UpdateClientInput) {
        return request<ConsoleUpdateClientMutation, ConsoleUpdateClientMutationVariables>(
          ConsoleUpdateClientDocument,
          { input: { ...input, clientMutationId: nextClientMutationId() } },
          'ConsoleUpdateClient',
        )
      },
      enable(input: ClientStateInput) {
        return request<ConsoleEnableClientMutation, ConsoleEnableClientMutationVariables>(
          ConsoleEnableClientDocument,
          { input: { ...input, clientMutationId: nextClientMutationId() } },
          'ConsoleEnableClient',
        )
      },
      disable(input: ClientStateInput) {
        return request<ConsoleDisableClientMutation, ConsoleDisableClientMutationVariables>(
          ConsoleDisableClientDocument,
          { input: { ...input, clientMutationId: nextClientMutationId() } },
          'ConsoleDisableClient',
        )
      },
      remove(input: ClientStateInput) {
        return request<ConsoleDeleteClientMutation, ConsoleDeleteClientMutationVariables>(
          ConsoleDeleteClientDocument,
          { input: { ...input, clientMutationId: nextClientMutationId() } },
          'ConsoleDeleteClient',
        )
      },
      createSecret(input: CreateClientSecretInput) {
        return request<
          ConsoleCreateClientSecretMutation,
          ConsoleCreateClientSecretMutationVariables
        >(
          ConsoleCreateClientSecretDocument,
          { input: { ...input, clientMutationId: nextClientMutationId() } },
          'ConsoleCreateClientSecret',
        )
      },
      rotateSecret(input: RotateClientSecretInput) {
        return request<
          ConsoleRotateClientSecretMutation,
          ConsoleRotateClientSecretMutationVariables
        >(
          ConsoleRotateClientSecretDocument,
          { input: { ...input, clientMutationId: nextClientMutationId() } },
          'ConsoleRotateClientSecret',
        )
      },
      revokeCredential(input: RevokeClientCredentialInput) {
        return request<
          ConsoleRevokeClientCredentialMutation,
          ConsoleRevokeClientCredentialMutationVariables
        >(
          ConsoleRevokeClientCredentialDocument,
          { input: { ...input, clientMutationId: nextClientMutationId() } },
          'ConsoleRevokeClientCredential',
        )
      },
      setScopes(input: SetClientScopesInput) {
        return request<ConsoleSetClientScopesMutation, ConsoleSetClientScopesMutationVariables>(
          ConsoleSetClientScopesDocument,
          { input: { ...input, clientMutationId: nextClientMutationId() } },
          'ConsoleSetClientScopes',
        )
      },
    }),
    [request],
  )
}
