import { Button, Dropdown, Label } from '@heroui/react'
import { Ellipsis } from 'lucide-react'
import { useEffect, useRef, useState, type ReactNode } from 'react'
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
  const popoverRef = useRef<HTMLDivElement>(null)
  const [restoreAfterEscape, setRestoreAfterEscape] = useState(false)
  useEffect(() => {
    if (isOpen || !restoreAfterEscape) return
    let cancelled = false
    // Restore after the overlay's exit animation and focus-scope cleanup, not during containment.
    requestAnimationFrame(async () => {
      const animations = popoverRef.current?.getAnimations?.() ?? []
      await Promise.allSettled(
        animations.map((animation) => animation.finished),
      )
      requestAnimationFrame(() =>
        requestAnimationFrame(() => {
          if (!cancelled) {
            triggerRef.current?.focus()
            setRestoreAfterEscape(false)
          }
        }),
      )
    })
    return () => {
      cancelled = true
    }
  }, [isOpen, restoreAfterEscape])
  const t = useTranslator()
  if (!actions.length) return null
  const label = t('tableRowActionsFor', { name: subject })
  return (
    <div
      className="inline-flex"
      onKeyDownCapture={(event) => {
        if (event.key === 'Escape') setRestoreAfterEscape(true)
      }}
      onKeyDown={(event) => {
        // Portaled menu events still bubble to the table through the React tree.
        if (event.key === 'Escape' && isOpen) {
          event.preventDefault()
          setOpen(false)
        }
        if (event.key !== 'Tab') event.stopPropagation()
      }}
    >
      <Dropdown
        isOpen={isOpen}
        onOpenChange={(open) => {
          setOpen(open)
          if (open) setRestoreAfterEscape(false)
        }}
      >
        <Button
          ref={triggerRef}
          isIconOnly
          size="sm"
          variant="ghost"
          aria-label={label}
          isDisabled={actions.every((action) => action.isDisabled)}
        >
          <Ellipsis className="size-4" aria-hidden="true" />
        </Button>
        <Dropdown.Popover
          ref={popoverRef}
          placement="bottom end"
          className="min-w-44"
        >
          <Dropdown.Menu
            aria-label={t('tableRowActions')}
            disabledKeys={actions
              .filter((action) => action.isDisabled)
              .map((action) => action.id)}
            onAction={(key) => {
              const action = actions.find((item) => item.id === key)
              if (action && !action.isDisabled) {
                // Dialogs must restore focus to the persistent row trigger, not a menu item that is removed.
                triggerRef.current?.focus()
                action.onAction()
              }
            }}
          >
            {actions.map((action) => (
              <Dropdown.Item
                key={action.id}
                id={action.id}
                textValue={action.label}
                variant={action.danger ? 'danger' : 'default'}
              >
                {action.icon}
                <Label>{action.label}</Label>
              </Dropdown.Item>
            ))}
          </Dropdown.Menu>
        </Dropdown.Popover>
      </Dropdown>
    </div>
  )
}
