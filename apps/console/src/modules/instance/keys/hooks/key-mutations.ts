import { useMemo } from 'react'

import {
  ConsoleCreateSigningKeyDocument,
  ConsoleKeysDocument,
  ConsoleRevokeKeyDocument,
  ConsoleRotateAndRevokeKeyDocument,
  ConsoleRotateKeyDocument,
  type ConsoleCreateSigningKeyMutation,
  type ConsoleCreateSigningKeyMutationVariables,
  type ConsoleRevokeKeyMutation,
  type ConsoleRevokeKeyMutationVariables,
  type ConsoleRotateAndRevokeKeyMutation,
  type ConsoleRotateAndRevokeKeyMutationVariables,
  type ConsoleRotateKeyMutation,
  type ConsoleRotateKeyMutationVariables,
  type KeyAlgorithm,
  type SigningAlgorithm,
} from '#/generated/graphql'
import { nextClientMutationId } from '#/lib/graphql/mutation-id'
import { useGraphQLMutation } from '#/lib/graphql/use-graphql-mutation'

export function useKeyMutations() {
  const request = useGraphQLMutation()
  return useMemo(
    () => ({
      createSigning(algorithm: SigningAlgorithm, keyAlgorithm: KeyAlgorithm) {
        return request<
          ConsoleCreateSigningKeyMutation,
          ConsoleCreateSigningKeyMutationVariables
        >(
          ConsoleCreateSigningKeyDocument,
          { input: { algorithm, keyAlgorithm, clientMutationId: nextClientMutationId() } },
          [ConsoleKeysDocument],
        )
      },
      rotate(id: string) {
        return request<ConsoleRotateKeyMutation, ConsoleRotateKeyMutationVariables>(
          ConsoleRotateKeyDocument,
          { input: { id, clientMutationId: nextClientMutationId() } },
          [ConsoleKeysDocument],
        )
      },
      rotateAndRevoke(id: string) {
        return request<
          ConsoleRotateAndRevokeKeyMutation,
          ConsoleRotateAndRevokeKeyMutationVariables
        >(
          ConsoleRotateAndRevokeKeyDocument,
          { input: { id, clientMutationId: nextClientMutationId() } },
          [ConsoleKeysDocument],
        )
      },
      revoke(id: string) {
        return request<ConsoleRevokeKeyMutation, ConsoleRevokeKeyMutationVariables>(
          ConsoleRevokeKeyDocument,
          { input: { id, clientMutationId: nextClientMutationId() } },
          [ConsoleKeysDocument],
        )
      },
    }),
    [request],
  )
}
