import { useMemo } from 'react'

import {
  ConsoleInstanceSettingsDocument,
  ConsoleUpdateAuthenticationSettingsDocument,
  ConsoleUpdateProtocolSettingsDocument,
  type ConsoleUpdateAuthenticationSettingsMutation,
  type ConsoleUpdateAuthenticationSettingsMutationVariables,
  type ConsoleUpdateProtocolSettingsMutation,
  type ConsoleUpdateProtocolSettingsMutationVariables,
  type UpdateAuthenticationSettingsInput,
  type UpdateProtocolSettingsInput,
} from '#/generated/graphql'
import { nextClientMutationId } from '#/lib/graphql/mutation-id'
import { useGraphQLMutation } from '#/lib/graphql/use-graphql-mutation'

export function useSettingMutations() {
  const request = useGraphQLMutation()
  return useMemo(
    () => ({
      updateProtocol(input: Omit<UpdateProtocolSettingsInput, 'clientMutationId'>) {
        return request<
          ConsoleUpdateProtocolSettingsMutation,
          ConsoleUpdateProtocolSettingsMutationVariables
        >(
          ConsoleUpdateProtocolSettingsDocument,
          { input: { ...input, clientMutationId: nextClientMutationId() } },
          [ConsoleInstanceSettingsDocument],
        )
      },
      updateAuthentication(input: Omit<UpdateAuthenticationSettingsInput, 'clientMutationId'>) {
        return request<
          ConsoleUpdateAuthenticationSettingsMutation,
          ConsoleUpdateAuthenticationSettingsMutationVariables
        >(
          ConsoleUpdateAuthenticationSettingsDocument,
          { input: { ...input, clientMutationId: nextClientMutationId() } },
          [ConsoleInstanceSettingsDocument],
        )
      },
    }),
    [request],
  )
}
