import { Button } from '@identity/ui/components/button'
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from '@identity/ui/components/dropdown-menu'
import { Ellipsis } from 'lucide-react'
import { useRef, useState, type ReactNode } from 'react'
import { useTranslator } from '#/lib/i18n'

export interface TableRowAction {
  id: string
  label: string
  onAction: () => void
  icon?: ReactNode
  isDisabled?: boolean
  danger?: boolean
}

/** Presentation only: modules own admission checks, navigation and confirmation state. */
export function TableRowActions({
  subject,
  actions,
}: {
  subject: string
  actions: readonly TableRowAction[]
}) {
  const [isOpen, setOpen] = useState(false)
  const triggerRef = useRef<HTMLButtonElement>(null)
  const t = useTranslator()
  if (!actions.length) return null
  const label = t('tableRowActionsFor', { name: subject })
  return (
    <div
      className="inline-flex"
      onKeyDown={(event) => {
        // Portaled menu events still bubble to the table through the React tree.
        if (event.key !== 'Tab') event.stopPropagation()
      }}
    >
      <DropdownMenu open={isOpen} onOpenChange={setOpen}>
        <DropdownMenuTrigger
          render={
            <Button
              ref={triggerRef}
              size="icon-sm"
              variant="ghost"
              aria-label={label}
              disabled={actions.every((action) => action.isDisabled)}
            />
          }
        >
          <Ellipsis className="size-4" aria-hidden="true" />
        </DropdownMenuTrigger>
        <DropdownMenuContent align="end" className="min-w-44">
          {actions.map((action) => (
            <DropdownMenuItem
              key={action.id}
              disabled={action.isDisabled}
              variant={action.danger ? 'destructive' : 'default'}
              onClick={() => {
                // Dialogs must restore focus to the persistent row trigger, not a menu item that is removed.
                triggerRef.current?.focus()
                action.onAction()
              }}
            >
              {action.icon}
              {action.label}
            </DropdownMenuItem>
          ))}
        </DropdownMenuContent>
      </DropdownMenu>
    </div>
  )
}
