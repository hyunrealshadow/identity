import { Button } from '@identity/ui/components/button'
import { RotateCcw, Save } from 'lucide-react'
import type { ReactNode } from 'react'

import { useTranslator } from '#/lib/i18n'

/** Save and discard controls below an editable settings form. */
export function SettingsFormFooter({
  dirty,
  pending,
  onDiscard,
  note,
  leading,
}: {
  dirty: boolean
  pending: boolean
  onDiscard: () => void
  note?: string
  leading?: ReactNode
}) {
  const t = useTranslator()
  return (
    <div
      className={`flex flex-wrap items-center gap-3 ${leading ? 'justify-between' : 'justify-end'}`}
    >
      {leading ? <div className="flex flex-wrap items-center gap-3">{leading}</div> : null}
      <div className="flex flex-wrap items-center justify-end gap-3">
        {dirty && note ? <span className="text-xs text-muted-foreground">{note}</span> : null}
        <Button type="button" variant="ghost" disabled={pending || !dirty} onClick={onDiscard}>
          <RotateCcw className="size-4" aria-hidden="true" />
          {t('settingsDiscard')}
        </Button>
        <Button type="submit" disabled={!dirty} loading={pending}>
          {pending ? null : <Save className="size-4" aria-hidden="true" />}
          {t('settingsSave')}
        </Button>
      </div>
    </div>
  )
}

/** The message under a row whose value needs attention. */
export function SettingsFieldError({ id, message }: { id: string; message?: string }) {
  return message ? (
    <p id={id} role="alert" className="mt-2 text-right text-xs leading-5 text-destructive">
      {message}
    </p>
  ) : null
}
