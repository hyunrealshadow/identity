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
} from '#/generated/graphql'
import { nextClientMutationId } from '#/lib/graphql/mutation-id'
import { useGraphQLMutation } from '#/lib/graphql/use-graphql-mutation'

export function useEmailMutations() {
  const request = useGraphQLMutation()
  return useMemo(
    () => ({
      updateDelivery(input: Omit<UpdateEmailDeliverySettingsInput, 'clientMutationId'>) {
        return request<
          ConsoleUpdateEmailDeliverySettingsMutation,
          ConsoleUpdateEmailDeliverySettingsMutationVariables
        >(
          ConsoleUpdateEmailDeliverySettingsDocument,
          { input: { ...input, clientMutationId: nextClientMutationId() } },
          [ConsoleInstanceSettingsDocument],
        )
      },
      updateTemplate(input: Omit<UpdateEmailTemplateInput, 'clientMutationId'>) {
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
