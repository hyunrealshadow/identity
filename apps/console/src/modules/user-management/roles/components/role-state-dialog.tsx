import { Button } from '@identity/ui/components/button'
import {
  Dialog,
  DialogContent,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@identity/ui/components/dialog'
import type { OverlayState } from '@identity/ui/hooks/use-overlay-state'
import { useEffect, useRef, useState } from 'react'

import type { RoleStateInput } from '#/generated/graphql'
import { useLocale, useTranslator } from '#/lib/i18n'
import { toast } from '#/lib/toast'
import { RbacMutationFeedback } from '#/components/rbac-feedback'
import type { RbacFeedbackState } from '#/lib/rbac-errors'
import { useRoleMutations } from '../hooks/role-mutations'
import {
  roleDisplayName,
  roleIsBuiltIn,
  type RoleDisplayFields,
} from '#/lib/localized-display'

/** What the state dialog needs, from either the role list or its detail. */
export type RoleLifecycleTarget = RoleDisplayFields & { id: string; version: string }

export function RoleStateDialog({
  state,
  action,
  role,
  onCommitted,
}: {
  state: OverlayState
  action: 'enable' | 'disable'
  role: RoleLifecycleTarget
  onCommitted: () => void
}) {
  const t = useTranslator()
  const { locale } = useLocale()
  const mutations = useRoleMutations()
  const displayName = roleDisplayName(role, locale)
  const [feedback, setFeedback] = useState<RbacFeedbackState | null>(null)
  const [pending, setPending] = useState(false)
  const submitting = useRef(false)

  useEffect(() => {
    if (state.isOpen) return
    setFeedback(null)
    setPending(false)
  }, [state.isOpen])

  async function submit() {
    if (submitting.current) return
    if (roleIsBuiltIn(role)) return
    submitting.current = true
    setPending(true)
    setFeedback(null)
    const input: RoleStateInput = {
      id: role.id,
      expectedVersion: role.version,
    }
    try {
      const result =
        action === 'enable'
          ? await mutations.enable(input)
          : await mutations.disable(input)
      const data = result.data as {
        enableRole?: { roleId: string; version: string } | null
        disableRole?: { roleId: string; version: string } | null
      } | null
      const payload = data?.enableRole ?? data?.disableRole ?? null
      if (!payload) {
        setFeedback({
          errors: result.errors,
          failure: result.failure ?? {
            kind: 'invalid_response',
            code: 'missing_role_state_payload',
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
        t(action === 'enable' ? 'rolesEnabledToast' : 'rolesDisabledToast'),
        { description: t('roleSettingsCommitted') },
      )
      if (result.partial) toast.warning(t('rbacPartialMutationNote'))
      onCommitted()
    } catch {
      setFeedback({
        errors: [],
        failure: { kind: 'network', code: 'role_state_request_failed' },
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
                action === 'enable' ? 'rolesEnableTitle' : 'rolesDisableTitle',
              )}
            </DialogTitle>
          </DialogHeader>
          <div>
            <p className="text-sm leading-6 text-muted-foreground">
              {t(
                action === 'enable'
                  ? 'rolesEnableDescription'
                  : 'rolesDisableDescription',
              )}
            </p>
            <p className="mt-3 text-sm font-medium">{displayName}</p>
            {feedback ? (
              <div className="mt-4">
                <RbacMutationFeedback feedback={feedback} />
              </div>
            ) : null}
          </div>
          <DialogFooter>
            <Button
              variant="outline"
              disabled={pending}
              onClick={() => state.close()}
            >
              {t('cancel')}
            </Button>
            <Button
              variant={action === 'disable' ? 'destructive' : 'default'}
              disabled={!role.version}
              loading={pending}
              onClick={() => void submit()}
            >
              {t(
                action === 'enable'
                  ? 'rolesEnableConfirm'
                  : 'rolesDisableConfirm',
              )}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </>
  )
}
