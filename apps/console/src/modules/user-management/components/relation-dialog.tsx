import { Button } from '@identity/ui/components/button'
import {
  Dialog,
  DialogContent,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@identity/ui/components/dialog'
import { Spinner } from '@identity/ui/components/spinner'
import type { ReactNode } from 'react'

import { useTranslator, type MessageKey } from '#/lib/i18n'
import { rbacConflict } from '../lib/rbac-errors'
import type { useRelationMutation } from '../lib/relation-mutation'
import { RbacMutationFeedback } from './rbac-feedback'

type OverlayState = {
  isOpen: boolean
  setOpen: (open: boolean) => void
  open: () => void
  close: () => void
  toggle: () => void
}

export function RelationDialog({
  state,
  mutation,
  title,
  confirm,
  danger = false,
  size = 'lg',
  disabled = false,
  children,
  error,
  onSubmit,
  onReload,
  reloadPending,
  conflictTitleKey,
  conflictDescriptionKey,
  bodyClassName,
  dialogClassName,
}: {
  state: OverlayState
  mutation: ReturnType<typeof useRelationMutation>
  title: string
  confirm: string
  danger?: boolean
  size?: 'md' | 'lg'
  disabled?: boolean
  children: ReactNode
  error?: string | null
  onSubmit: () => void
  onReload: () => void
  reloadPending: boolean
  conflictTitleKey?: MessageKey
  conflictDescriptionKey?: MessageKey
  bodyClassName?: string
  dialogClassName?: string
}) {
  const t = useTranslator()
  const { pending, feedback, setFeedback } = mutation
  return (
    <Dialog
      open={state.isOpen}
      onOpenChange={(open) => {
        if (!open && pending) return
        state.setOpen(open)
      }}
    >
      <DialogContent
        showCloseButton={!pending}
        closeLabel={t('close')}
        className={[
          size === 'lg' ? 'sm:max-w-lg' : undefined,
          dialogClassName,
        ]
          .filter(Boolean)
          .join(' ')}
      >
        <DialogHeader>
          <DialogTitle>{title}</DialogTitle>
        </DialogHeader>
        <div
          className={[
            bodyClassName,
            'max-h-[calc(100dvh-12rem)] overflow-y-auto',
          ]
            .filter(Boolean)
            .join(' ')}
        >
          {children}
          {error ? (
            <p role="alert" className="mt-3 text-xs text-destructive">
              {error}
            </p>
          ) : null}
          {feedback ? (
            <div className="mt-4">
              <RbacMutationFeedback
                feedback={feedback}
                conflictTitleKey={conflictTitleKey}
                conflictDescriptionKey={conflictDescriptionKey}
                reloadPending={reloadPending}
                onReload={() => {
                  setFeedback(null)
                  onReload()
                }}
              />
            </div>
          ) : null}
        </div>
        <DialogFooter>
          <Button
            type="button"
            variant="secondary"
            disabled={pending}
            onClick={() => state.close()}
          >
            {t('cancel')}
          </Button>
          <Button
            type="button"
            variant={danger ? 'destructive' : 'default'}
            disabled={
              pending ||
              reloadPending ||
              disabled ||
              Boolean(feedback && rbacConflict(feedback.errors).conflict)
            }
            onClick={onSubmit}
          >
            {pending ? <Spinner aria-label={t('working')} /> : null}
            {confirm}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}
