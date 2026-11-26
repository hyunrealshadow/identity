import type { OverlayState } from '@identity/ui/hooks/use-overlay-state'
import { useEffect, useState } from 'react'

import { ConfirmationDialog } from '#/components/confirmation-dialog'
import { useLocale, useTranslator } from '#/lib/i18n'
import { toast } from '#/lib/toast'
import { RbacMutationFeedback } from '#/components/rbac-feedback'
import {
  resolveLocalizedText,
  type LocalizedEntry,
} from '#/lib/localized-metadata'
import type { RbacFeedbackState } from '#/lib/rbac-errors'
import { useClientMutations } from '../hooks/client-mutations'
import { mutationFeedback } from '../hooks/use-client-editor'

/** What the lifecycle dialogs need, from either the client list or its detail. */
export interface ClientLifecycleTarget {
  id: string
  version: string
  enabled: boolean
  name: string
  names: ReadonlyArray<LocalizedEntry>
}

function useDialogFeedback(state: OverlayState) {
  const [feedback, setFeedback] = useState<RbacFeedbackState | null>(null)
  const [pending, setPending] = useState(false)
  useEffect(() => {
    if (!state.isOpen) setFeedback(null)
  }, [state.isOpen])
  return { feedback, setFeedback, pending, setPending }
}

/** Enables or disables a client; failures stay in the dialog. */
export function ClientStateDialog({
  state,
  client,
  onCommitted,
}: {
  state: OverlayState
  client: ClientLifecycleTarget
  onCommitted?: () => void
}) {
  const t = useTranslator()
  const mutations = useClientMutations()
  const { feedback, setFeedback, pending, setPending } = useDialogFeedback(state)

  async function toggle() {
    setPending(true)
    setFeedback(null)
    try {
      const input = { id: client.id, expectedVersion: client.version }
      if (client.enabled) {
        const result = await mutations.disable(input)
        if (!result.data?.disableClient) {
          setFeedback(mutationFeedback(result, 'missing_client_state_payload'))
          return
        }
      } else {
        const result = await mutations.enable(input)
        if (!result.data?.enableClient) {
          setFeedback(mutationFeedback(result, 'missing_client_state_payload'))
          return
        }
      }
      state.close()
      toast.success(t(client.enabled ? 'clientsDisabledToast' : 'clientsEnabledToast'))
      onCommitted?.()
    } catch {
      setFeedback({
        errors: [],
        failure: { kind: 'network', code: 'client_state_request_failed' },
        forbidden: false,
      })
    } finally {
      setPending(false)
    }
  }

  return (
    <ConfirmationDialog
      state={state}
      title={t(client.enabled ? 'clientsDisableTitle' : 'clientsEnableTitle')}
      description={t(client.enabled ? 'clientsDisableDescription' : 'clientsEnableDescription')}
      confirmLabel={t(client.enabled ? 'clientsDisable' : 'clientsEnable')}
      destructive={client.enabled}
      pending={pending}
      onConfirm={() => void toggle()}
    >
      {feedback ? <RbacMutationFeedback feedback={feedback} /> : null}
    </ConfirmationDialog>
  )
}

/** Deletes a client; failures stay in the dialog. */
export function ClientDeleteDialog({
  state,
  client,
  onCommitted,
}: {
  state: OverlayState
  client: ClientLifecycleTarget
  onCommitted?: () => void
}) {
  const t = useTranslator()
  const { locale } = useLocale()
  const mutations = useClientMutations()
  const { feedback, setFeedback, pending, setPending } = useDialogFeedback(state)

  async function remove() {
    setPending(true)
    setFeedback(null)
    try {
      const result = await mutations.remove({
        id: client.id,
        expectedVersion: client.version,
      })
      if (!result.data?.deleteClient) {
        setFeedback(mutationFeedback(result, 'missing_delete_client_payload'))
        return
      }
      state.close()
      toast.success(t('clientsDeletedToast'))
      onCommitted?.()
    } catch {
      setFeedback({
        errors: [],
        failure: { kind: 'network', code: 'client_delete_request_failed' },
        forbidden: false,
      })
    } finally {
      setPending(false)
    }
  }

  return (
    <ConfirmationDialog
      state={state}
      title={t('clientsDeleteTitle')}
      description={t('clientsDeleteDescription', {
        name: resolveLocalizedText(client.names, locale) ?? client.name,
      })}
      confirmLabel={t('clientsDelete')}
      destructive
      pending={pending}
      onConfirm={() => void remove()}
    >
      {feedback ? <RbacMutationFeedback feedback={feedback} /> : null}
    </ConfirmationDialog>
  )
}
