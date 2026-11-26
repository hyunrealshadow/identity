import { Button } from '@identity/ui/components/button'
import {
  Dialog,
  DialogContent,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@identity/ui/components/dialog'
import type { OverlayState } from '@identity/ui/hooks/use-overlay-state'
import { useRef, useState } from 'react'

import type { GroupStateInput, SetGroupEnabledInput } from '#/generated/graphql'
import { useLocale, useTranslator } from '#/lib/i18n'
import { toast } from '#/lib/toast'
import { RbacMutationFeedback } from '#/components/rbac-feedback'
import { useGroupMutations } from '#/modules/user-management/groups/hooks/group-mutations'
import {
  resolveLocalizedText,
  type LocalizedEntry,
} from '#/lib/localized-metadata'
import type { RbacFeedbackState } from '#/lib/rbac-errors'

/** What the lifecycle dialogs need, from either the group list or its detail. */
export interface GroupLifecycleTarget {
  id: string
  version: string
  name?: string | null
  names: ReadonlyArray<LocalizedEntry>
}

export function GroupStateDialog({
  state,
  action,
  group,
  onCommitted,
  onReload,
}: {
  state: OverlayState
  action: 'enable' | 'disable'
  group: GroupLifecycleTarget
  onCommitted: () => void
  onReload: () => void
}) {
  const t = useTranslator()
  const { locale } = useLocale()
  const mutations = useGroupMutations()
  const displayName =
    resolveLocalizedText(group.names, locale) ?? group.name ?? group.id
  const [feedback, setFeedback] = useState<RbacFeedbackState | null>(null)
  const [pending, setPending] = useState(false)
  const submitting = useRef(false)

  async function submit() {
    if (submitting.current) return
    submitting.current = true
    setPending(true)
    setFeedback(null)
    const input: SetGroupEnabledInput = {
      id: group.id,
      enabled: action === 'enable',
      expectedVersion: group.version,
    }
    try {
      const result = await mutations.setEnabled(input)
      const payload = result.data?.setGroupEnabled ?? null
      if (!payload) {
        setFeedback({
          errors: result.errors,
          failure: result.failure ?? {
            kind: 'invalid_response',
            code: 'missing_group_state_payload',
            requestId: result.requestId,
            traceId: result.traceId,
          },
          stepUp: result.stepUp,
          requestId: result.requestId,
          traceId: result.traceId,
          forbidden: result.forbidden,
        })
        return
      }
      state.close()
      toast.success(
        t(action === 'enable' ? 'groupsEnabledToast' : 'groupsDisabledToast'),
        { description: t('groupSettingsCommitted') },
      )
      if (result.partial) toast.warning(t('rbacPartialMutationNote'))
      onCommitted()
    } catch {
      setFeedback({
        errors: [],
        failure: { kind: 'network', code: 'group_state_request_failed' },
        forbidden: false,
      })
    } finally {
      submitting.current = false
      setPending(false)
    }
  }

  return (
    <>
      <Dialog
        open={state.isOpen}
        onOpenChange={(open) => {
          if (!open && pending) return
          state.setOpen(open)
        }}
      >
        <DialogContent showCloseButton={!pending} closeLabel={t('close')}>
          <DialogHeader>
            <DialogTitle>
              {t(
                action === 'enable'
                  ? 'groupsEnableTitle'
                  : 'groupsDisableTitle',
              )}
            </DialogTitle>
          </DialogHeader>
          <div>
            <p className="text-sm leading-6 text-muted-foreground">
              {t(
                action === 'enable'
                  ? 'groupsEnableDescription'
                  : 'groupsDisableDescription',
              )}
            </p>
            <p className="mt-3 text-sm font-medium">{displayName}</p>
            {feedback ? (
              <div className="mt-4">
                <RbacMutationFeedback feedback={feedback} onReload={onReload} />
              </div>
            ) : null}
          </div>
          <DialogFooter>
            <Button
              type="button"
              variant="outline"
              disabled={pending}
              onClick={() => state.close()}
            >
              {t('cancel')}
            </Button>
            <Button
              type="button"
              variant={action === 'disable' ? 'destructive' : 'default'}
              disabled={!group.version}
              loading={pending}
              onClick={() => void submit()}
            >
              {t(
                action === 'enable'
                  ? 'groupsEnableConfirm'
                  : 'groupsDisableConfirm',
              )}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </>
  )
}

export function GroupDeleteDialog({
  state,
  group,
  onCommitted,
  onReload,
}: {
  state: OverlayState
  group: GroupLifecycleTarget
  onCommitted: () => void
  onReload: () => void
}) {
  const t = useTranslator()
  const { locale } = useLocale()
  const mutations = useGroupMutations()
  const displayName =
    resolveLocalizedText(group.names, locale) ?? group.name ?? group.id
  const [feedback, setFeedback] = useState<RbacFeedbackState | null>(null)
  const [pending, setPending] = useState(false)
  const submitting = useRef(false)

  async function submit() {
    if (submitting.current) return
    submitting.current = true
    setPending(true)
    setFeedback(null)
    const input: GroupStateInput = {
      id: group.id,
      expectedVersion: group.version,
    }
    try {
      const result = await mutations.remove(input)
      const payload = result.data?.deleteGroup ?? null
      if (!payload || !payload.deleted) {
        setFeedback({
          errors: result.errors,
          failure: result.failure ?? {
            kind: 'invalid_response',
            code: 'missing_delete_group_payload',
            requestId: result.requestId,
            traceId: result.traceId,
          },
          stepUp: result.stepUp,
          requestId: result.requestId,
          traceId: result.traceId,
          forbidden: result.forbidden,
        })
        return
      }
      state.close()
      if (result.partial) toast.warning(t('rbacPartialMutationNote'))
      onCommitted()
    } catch {
      setFeedback({
        errors: [],
        failure: { kind: 'network', code: 'group_delete_request_failed' },
        forbidden: false,
      })
    } finally {
      submitting.current = false
      setPending(false)
    }
  }

  return (
    <>
      <Dialog
        open={state.isOpen}
        onOpenChange={(open) => {
          if (!open && pending) return
          state.setOpen(open)
        }}
      >
        <DialogContent showCloseButton={!pending} closeLabel={t('close')}>
          <DialogHeader>
            <DialogTitle>{t('groupsDeleteTitle')}</DialogTitle>
          </DialogHeader>
          <div>
            <p className="text-sm leading-6 text-muted-foreground">
              {t('groupsDeleteDescription', { name: displayName })}
            </p>
            {feedback ? (
              <div className="mt-4">
                <RbacMutationFeedback feedback={feedback} onReload={onReload} />
              </div>
            ) : null}
          </div>
          <DialogFooter>
            <Button
              type="button"
              variant="outline"
              disabled={pending}
              onClick={() => state.close()}
            >
              {t('cancel')}
            </Button>
            <Button
              type="button"
              variant="destructive"
              disabled={!group.version}
              loading={pending}
              onClick={() => void submit()}
            >
              {t('groupsDeleteConfirm')}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </>
  )
}
