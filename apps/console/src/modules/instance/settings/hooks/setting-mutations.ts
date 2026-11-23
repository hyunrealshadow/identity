import { useMemo } from 'react'

import {
  ConsoleInstanceSettingsDocument,
  ConsoleSendTestEmailDocument,
  ConsoleUpdateEmailDeliverySettingsDocument,
  ConsoleUpdateEmailTemplateDocument,
  type ConsoleSendTestEmailMutation,
  type ConsoleSendTestEmailMutationVariables,
  type ConsoleUpdateEmailDeliverySettingsMutation,
  type ConsoleUpdateEmailDeliverySettingsMutationVariables,
  type ConsoleUpdateEmailTemplateMutation,
  type ConsoleUpdateEmailTemplateMutationVariables,
  type SendTestEmailInput,
  type UpdateEmailDeliverySettingsInput,
  type UpdateEmailTemplateInput,
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
      updateEmailDelivery(input: Omit<UpdateEmailDeliverySettingsInput, 'clientMutationId'>) {
        return request<
          ConsoleUpdateEmailDeliverySettingsMutation,
          ConsoleUpdateEmailDeliverySettingsMutationVariables
        >(
          ConsoleUpdateEmailDeliverySettingsDocument,
          { input: { ...input, clientMutationId: nextClientMutationId() } },
          [ConsoleInstanceSettingsDocument],
        )
      },
      updateEmailTemplate(input: Omit<UpdateEmailTemplateInput, 'clientMutationId'>) {
        return request<
          ConsoleUpdateEmailTemplateMutation,
          ConsoleUpdateEmailTemplateMutationVariables
        >(
          ConsoleUpdateEmailTemplateDocument,
          { input: { ...input, clientMutationId: nextClientMutationId() } },
          [ConsoleInstanceSettingsDocument],
        )
      },
      sendTestEmail(input: Omit<SendTestEmailInput, 'clientMutationId'>) {
        return request<ConsoleSendTestEmailMutation, ConsoleSendTestEmailMutationVariables>(
          ConsoleSendTestEmailDocument,
          { input: { ...input, clientMutationId: nextClientMutationId() } },
        )
      },
    }),
    [request],
  )
}
