import {
  Alert,
  AlertDescription,
  AlertTitle,
} from '@identity/ui/components/alert'
import { Button } from '@identity/ui/components/button'
import { Spinner } from '@identity/ui/components/spinner'
import { Info, Save } from 'lucide-react'
import type { ReactNode } from 'react'

import { useTranslator } from '#/lib/i18n'
import { RbacMutationFeedback } from '#/modules/user-management/components/rbac-feedback'
import type { ClientEditor } from '../hooks/use-client-editor'
import { useClientDetail, type ConsoleClient } from './client-detail-shell'

/** Whether the viewer may change this client's settings. */
export function useClientEditable(client: ConsoleClient) {
  const { scope } = useClientDetail()
  return scope.update && !client.builtIn
}

/**
 * One tab's settings form: the built-in notice, mutation feedback, the
 * groups the tab owns and a save button that appears once something changed.
 */
export function ClientEditForm({
  client,
  editor,
  children,
  after,
}: {
  client: ConsoleClient
  editor: ClientEditor
  children: ReactNode
  /** Content outside the form, such as immediate actions with their own confirmation. */
  after?: ReactNode
}) {
  const t = useTranslator()
  const { query } = useClientDetail()
  const editable = useClientEditable(client)
  return (
    <div className="space-y-8">
      {client.builtIn ? (
        <Alert className="console-card border border-border">
          <Info aria-hidden="true" />
          <AlertTitle>{t('clientsBuiltInTitle')}</AlertTitle>
          <AlertDescription>{t('clientsBuiltInDescription')}</AlertDescription>
        </Alert>
      ) : null}
      {editor.feedback ? (
        <RbacMutationFeedback
          feedback={editor.feedback}
          onReload={() => void query.refresh()}
          reloadPending={query.refreshing}
        />
      ) : null}
      <form
        noValidate
        aria-busy={editor.pending}
        className="space-y-6"
        onSubmit={(event) => {
          event.preventDefault()
          void editor.save()
        }}
      >
        {children}
        {editable ? (
          <div className="flex flex-wrap items-center justify-end gap-3">
            {editor.dirty && editor.withdraws ? (
              <span className="text-xs text-muted-foreground">
                {t('clientsSettingsWithdrawNote')}
              </span>
            ) : null}
            <Button type="submit" disabled={editor.pending || !editor.dirty}>
              {editor.pending ? (
                <Spinner aria-label={t('clientsSavePending')} />
              ) : (
                <Save className="size-4" aria-hidden="true" />
              )}
              {t('clientsSave')}
            </Button>
          </div>
        ) : null}
      </form>
      {after}
    </div>
  )
}
