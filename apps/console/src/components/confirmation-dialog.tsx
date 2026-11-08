import { Button } from '@identity/ui/components/button'
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@identity/ui/components/dialog'
import { Spinner } from '@identity/ui/components/spinner'
import { useOverlayState } from '@identity/ui/hooks/use-overlay-state'
import type { ReactNode } from 'react'

import { useTranslator } from '#/lib/i18n'

export type ConfirmationState = ReturnType<typeof useOverlayState>

export function ConfirmationDialog({
  state,
  title,
  description,
  children,
  confirmLabel,
  cancelLabel,
  pending = false,
  destructive = false,
  onConfirm,
}: {
  state: ConfirmationState
  title: string
  description?: string
  children?: ReactNode
  confirmLabel?: string
  cancelLabel?: string
  pending?: boolean
  destructive?: boolean
  onConfirm: () => void
}) {
  const t = useTranslator()

  return (
    <Dialog
      open={state.isOpen}
      onOpenChange={(open) => {
        if (!open && pending) return
        state.setOpen(open)
      }}
    >
      <DialogContent showCloseButton={!pending} closeLabel={t('close')}>
        <DialogHeader>
          <DialogTitle>{title}</DialogTitle>
          {description ? <DialogDescription>{description}</DialogDescription> : null}
        </DialogHeader>
        {children ? <div className="text-sm leading-6">{children}</div> : null}
        <DialogFooter>
          <Button
            type="button"
            variant="secondary"
            disabled={pending}
            onClick={() => state.close()}
          >
            {cancelLabel ?? t('cancel')}
          </Button>
          <Button
            type="button"
            variant={destructive ? 'destructive' : 'default'}
            disabled={pending}
            onClick={onConfirm}
          >
            {pending ? <Spinner aria-label={t('working')} /> : null}
            {confirmLabel ?? t('confirm')}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}
