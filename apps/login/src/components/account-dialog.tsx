import { Button } from '@identity/ui/components/button'
import {
  Dialog,
  DialogClose,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from '@identity/ui/components/dialog'
import { cn } from '@identity/ui/lib/utils'
import { XIcon } from 'lucide-react'
import type { ReactNode } from 'react'

import type { DialogState } from './use-dialog-state'

/**
 * Account-center dialog. Outside clicks never dismiss it, so a half-finished
 * security step is not lost, and it stays open while `busy`.
 */
export function AccountDialog({ state, title, description, closeLabel, busy = false, className, children }: {
  state: DialogState
  title: ReactNode
  description?: ReactNode
  closeLabel: string
  busy?: boolean
  className?: string
  children: ReactNode
}) {
  return (
    <Dialog
      open={state.isOpen}
      disablePointerDismissal
      onOpenChange={(open) => {
        if (!open && busy) return
        state.setOpen(open)
      }}
    >
      <DialogContent
        showCloseButton={false}
        className={cn('max-h-[calc(100dvh-2rem)] overflow-y-auto sm:max-w-lg', className)}
      >
        <DialogClose
          disabled={busy}
          render={<Button variant="ghost" size="icon-sm" className="absolute top-4 right-4" />}
        >
          <XIcon aria-hidden="true" />
          <span className="sr-only">{closeLabel}</span>
        </DialogClose>
        <DialogHeader>
          <DialogTitle>{title}</DialogTitle>
          {description ? <DialogDescription>{description}</DialogDescription> : null}
        </DialogHeader>
        {children}
      </DialogContent>
    </Dialog>
  )
}
