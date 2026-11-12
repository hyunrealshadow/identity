import { Button } from '@identity/ui/components/button'
import { Spinner } from '@identity/ui/components/spinner'
import { RotateCcw, Save } from 'lucide-react'

import { useTranslator } from '#/lib/i18n'

/** Save and discard controls below an editable settings form. */
export function SettingsFormFooter({
  dirty,
  pending,
  onDiscard,
  note,
}: {
  dirty: boolean
  pending: boolean
  onDiscard: () => void
  note?: string
}) {
  const t = useTranslator()
  return (
    <div className="flex flex-wrap items-center justify-end gap-3">
      {dirty && note ? <span className="text-xs text-muted-foreground">{note}</span> : null}
      <Button type="button" variant="ghost" disabled={pending || !dirty} onClick={onDiscard}>
        <RotateCcw className="size-4" aria-hidden="true" />
        {t('settingsDiscard')}
      </Button>
      <Button type="submit" disabled={pending || !dirty}>
        {pending ? (
          <Spinner aria-label={t('settingsSavePending')} />
        ) : (
          <Save className="size-4" aria-hidden="true" />
        )}
        {t('settingsSave')}
      </Button>
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
