import { useMemo } from 'react'

import {
  ConsoleInstanceSettingsDocument,
  ConsoleUpdateAuthenticationSettingsDocument,
  ConsoleUpdateProtocolSettingsDocument,
  ConsoleUpdateSessionSettingsDocument,
  type ConsoleUpdateAuthenticationSettingsMutation,
  type ConsoleUpdateAuthenticationSettingsMutationVariables,
  type ConsoleUpdateProtocolSettingsMutation,
  type ConsoleUpdateProtocolSettingsMutationVariables,
  type ConsoleUpdateSessionSettingsMutation,
  type ConsoleUpdateSessionSettingsMutationVariables,
  type UpdateAuthenticationSettingsInput,
  type UpdateProtocolSettingsInput,
  type UpdateSessionSettingsInput,
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
      updateSession(input: Omit<UpdateSessionSettingsInput, 'clientMutationId'>) {
        return request<
          ConsoleUpdateSessionSettingsMutation,
          ConsoleUpdateSessionSettingsMutationVariables
        >(
          ConsoleUpdateSessionSettingsDocument,
          { input: { ...input, clientMutationId: nextClientMutationId() } },
          [ConsoleInstanceSettingsDocument],
        )
      },
    }),
    [request],
  )
}
