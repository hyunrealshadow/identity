import { Button } from '@identity/ui/components/button'
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from '@identity/ui/components/dropdown-menu'
import { Ellipsis } from 'lucide-react'
import { Fragment, useRef, useState } from 'react'

import { useTranslator, type MessageKey } from '#/lib/i18n'
import { toast } from '#/lib/toast'

/**
 * Where an action sits in a row menu. Sections always appear in this order,
 * separated by dividers:
 * - `open`: the row's own detail, or the object at the other end of a relation
 * - `navigate`: one frequently used sub-page
 * - `copy`: copy the row's ID when the table does not show it
 * - `state`: enable, disable, unlock, rotate
 * - `danger`: delete, remove, revoke; destructive and confirmed
 */
export type TableRowActionSection = 'open' | 'navigate' | 'copy' | 'state' | 'danger'

const SECTION_ORDER: readonly TableRowActionSection[] = [
  'open',
  'navigate',
  'copy',
  'state',
  'danger',
]

export interface TableRowAction {
  id: string
  label: string
  section: TableRowActionSection
  onAction: () => void
  /** Only for transient conditions such as a version still loading; hide actions that do not apply. */
  isDisabled?: boolean
}

/** Copies a row ID and reports the result; for tables without an ID column. */
export function copyIdAction(
  id: string,
  t: (key: MessageKey) => string,
): TableRowAction {
  return {
    id: 'copy-id',
    label: t('tableActionCopyId'),
    section: 'copy',
    onAction: () => {
      void navigator.clipboard.writeText(id).then(
        () => toast.success(t('valueCopied')),
        () => toast.error(t('valueCopyFailed')),
      )
    },
  }
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
  const sections = SECTION_ORDER.map((section) =>
    actions.filter((action) => action.section === section),
  ).filter((group) => group.length > 0)
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
          {sections.map((group, index) => (
            <Fragment key={group[0].section}>
              {index > 0 ? <DropdownMenuSeparator /> : null}
              {group.map((action) => (
                <DropdownMenuItem
                  key={action.id}
                  disabled={action.isDisabled}
                  variant={action.section === 'danger' ? 'destructive' : 'default'}
                  onClick={() => {
                    // Dialogs must restore focus to the persistent row trigger, not a menu item that is removed.
                    triggerRef.current?.focus()
                    action.onAction()
                  }}
                >
                  {action.label}
                </DropdownMenuItem>
              ))}
            </Fragment>
          ))}
        </DropdownMenuContent>
      </DropdownMenu>
    </div>
  )
}
