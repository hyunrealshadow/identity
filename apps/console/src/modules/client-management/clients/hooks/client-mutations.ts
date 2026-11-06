import { useMemo } from 'react'

import {
  ConsoleClientCredentialsDocument,
  ConsoleClientDocument,
  ConsoleClientScopesDocument,
  ConsoleClientsDocument,
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
} from '#/generated/graphql'
import { nextClientMutationId } from '#/lib/graphql/mutation-id'
import { useGraphQLMutation } from '#/lib/graphql/use-graphql-mutation'

export function useClientMutations() {
  const request = useGraphQLMutation()
  return useMemo(
    () => ({
      create(input: CreateClientInput) {
        return request<ConsoleCreateClientMutation, ConsoleCreateClientMutationVariables>(
          ConsoleCreateClientDocument,
          { input: { ...input, clientMutationId: nextClientMutationId() } },
          [ConsoleClientsDocument],
        )
      },
      update(input: UpdateClientInput) {
        return request<ConsoleUpdateClientMutation, ConsoleUpdateClientMutationVariables>(
          ConsoleUpdateClientDocument,
          { input: { ...input, clientMutationId: nextClientMutationId() } },
          // The credentials view carries the auth method and version too.
          [ConsoleClientDocument, ConsoleClientsDocument, ConsoleClientCredentialsDocument],
        )
      },
      enable(input: ClientStateInput) {
        return request<ConsoleEnableClientMutation, ConsoleEnableClientMutationVariables>(
          ConsoleEnableClientDocument,
          { input: { ...input, clientMutationId: nextClientMutationId() } },
          [ConsoleClientDocument, ConsoleClientsDocument],
        )
      },
      disable(input: ClientStateInput) {
        return request<ConsoleDisableClientMutation, ConsoleDisableClientMutationVariables>(
          ConsoleDisableClientDocument,
          { input: { ...input, clientMutationId: nextClientMutationId() } },
          [ConsoleClientDocument, ConsoleClientsDocument],
        )
      },
      remove(input: ClientStateInput) {
        return request<ConsoleDeleteClientMutation, ConsoleDeleteClientMutationVariables>(
          ConsoleDeleteClientDocument,
          { input: { ...input, clientMutationId: nextClientMutationId() } },
          [ConsoleClientDocument, ConsoleClientsDocument],
        )
      },
      createSecret(input: CreateClientSecretInput) {
        return request<
          ConsoleCreateClientSecretMutation,
          ConsoleCreateClientSecretMutationVariables
        >(
          ConsoleCreateClientSecretDocument,
          { input: { ...input, clientMutationId: nextClientMutationId() } },
          [ConsoleClientCredentialsDocument, ConsoleClientDocument],
        )
      },
      rotateSecret(input: RotateClientSecretInput) {
        return request<
          ConsoleRotateClientSecretMutation,
          ConsoleRotateClientSecretMutationVariables
        >(
          ConsoleRotateClientSecretDocument,
          { input: { ...input, clientMutationId: nextClientMutationId() } },
          [ConsoleClientCredentialsDocument, ConsoleClientDocument],
        )
      },
      revokeCredential(input: RevokeClientCredentialInput) {
        return request<
          ConsoleRevokeClientCredentialMutation,
          ConsoleRevokeClientCredentialMutationVariables
        >(
          ConsoleRevokeClientCredentialDocument,
          { input: { ...input, clientMutationId: nextClientMutationId() } },
          [ConsoleClientCredentialsDocument, ConsoleClientDocument],
        )
      },
      setScopes(input: SetClientScopesInput) {
        return request<ConsoleSetClientScopesMutation, ConsoleSetClientScopesMutationVariables>(
          ConsoleSetClientScopesDocument,
          { input: { ...input, clientMutationId: nextClientMutationId() } },
          [ConsoleClientScopesDocument, ConsoleClientDocument],
        )
      },
    }),
    [request],
  )
}
