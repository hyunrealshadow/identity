import {
  Alert,
  AlertDescription,
  AlertTitle,
} from '@identity/ui/components/alert'
import { Button } from '@identity/ui/components/button'
import { useOverlayState } from '@identity/ui/hooks/use-overlay-state'
import { useNavigate } from '@tanstack/react-router'
import { Power, Trash2, TriangleAlert } from 'lucide-react'
import { useEffect, useState } from 'react'

import { ConfirmationDialog } from '#/components/confirmation-dialog'
import { LocalizedTextField } from '#/components/localized-text-field'
import {
  SettingsGroup,
  SettingsGroupSkeleton,
  SettingsRow,
} from '#/components/settings-section'
import { formatDateTime } from '#/lib/format'
import { useLocale, useTranslator } from '#/lib/i18n'
import { toast } from '#/lib/toast'
import { RbacMutationFeedback } from '#/modules/user-management/components/rbac-feedback'
import { resolveLocalizedText } from '#/modules/user-management/groups/lib/groups-search'
import type { RbacFeedbackState } from '#/modules/user-management/lib/rbac-errors'
import { ApplicationLinkRows } from '../components/advanced-fields'
import { useClientDetail, type ConsoleClient } from '../components/client-detail-shell'
import { ClientEditForm, useClientEditable } from '../components/client-edit-form'
import { useClientMutations } from '../hooks/client-mutations'
import { mutationFeedback, useClientEditor } from '../hooks/use-client-editor'
import { formSeed } from '../lib/client-form'

export function ClientGeneralPage() {
  const { client } = useClientDetail()
  if (!client) return <ClientGeneralSkeleton />
  return <ClientGeneral key={formSeed(client)} client={client} />
}

/** Matches the groups below, in order, so loading keeps the layout. */
function ClientGeneralSkeleton() {
  return (
    <div className="space-y-6" aria-busy="true">
      <SettingsGroupSkeleton rows={['localized', 'localizedTextarea', 'value', 'value']} />
      <SettingsGroupSkeleton rows={['textarea', 'textarea', 'textarea', 'textarea', 'textarea']} />
    </div>
  )
}

function ClientGeneral({ client }: { client: ConsoleClient }) {
  const t = useTranslator()
  const { locale, timeZone } = useLocale()
  const { scope } = useClientDetail()
  const editor = useClientEditor(client)
  const disabled = editor.pending || !useClientEditable(client)
  const { text } = editor

  return (
    <ClientEditForm
      client={client}
      editor={editor}
      after={
        <>
          {!client.enabled ? (
            <Alert className="console-card border border-border text-warning">
              <TriangleAlert aria-hidden="true" />
              <AlertTitle>{t('clientsDisabledTitle')}</AlertTitle>
              <AlertDescription>{t('clientsDisabledDescription')}</AlertDescription>
            </Alert>
          ) : null}
          {!client.builtIn && (scope.state || scope.delete) ? (
            <ClientLifecycle client={client} />
          ) : null}
        </>
      }
    >
      <SettingsGroup title={t('clientsBasicSection')}>
        <SettingsRow>
          <LocalizedTextField
            name="names"
            label={t('localizedName')}
            defaultValue={text.name}
            onDefaultValueChange={(name) => editor.setText({ ...text, name })}
            value={text.names}
            onChange={(names) => editor.setText({ ...text, names })}
            isDisabled={disabled}
            isRequired
            maxLength={256}
            error={
              editor.nameError
                ? t(editor.nameError)
                : (editor.errors.text.name ?? editor.errors.text.names)
            }
          />
        </SettingsRow>
        <SettingsRow>
          <LocalizedTextField
            name="descriptions"
            label={t('localizedDescription')}
            defaultValue={text.description}
            onDefaultValueChange={(description) => editor.setText({ ...text, description })}
            value={text.descriptions}
            onChange={(descriptions) => editor.setText({ ...text, descriptions })}
            isDisabled={disabled}
            multiline
            maxLength={1024}
            error={editor.errors.text.description ?? editor.errors.text.descriptions}
          />
        </SettingsRow>
        <SettingsRow
          label={t('tableColumnCreated')}
          action={
            <span className="text-sm text-muted-foreground">
              {formatDateTime(client.createdAt, locale, timeZone)}
            </span>
          }
        />
        <SettingsRow
          label={t('clientsUpdated')}
          action={
            <span className="text-sm text-muted-foreground">
              {client.updatedAt
                ? formatDateTime(client.updatedAt, locale, timeZone)
                : t('clientsNeverUpdated')}
            </span>
          }
        />
      </SettingsGroup>

      <SettingsGroup
        title={t('clientsApplicationLinksSection')}
        description={t('clientsApplicationLinksSectionHint')}
      >
        <ApplicationLinkRows
          draft={editor.advanced}
          onChange={editor.setAdvanced}
          errors={editor.errors.advanced}
          isDisabled={disabled}
        />
      </SettingsGroup>
    </ClientEditForm>
  )
}

function ClientLifecycle({ client }: { client: ConsoleClient }) {
  const t = useTranslator()
  const { locale } = useLocale()
  const navigate = useNavigate()
  const { query, scope } = useClientDetail()
  const mutations = useClientMutations()
  const stateDialog = useOverlayState()
  const deleteDialog = useOverlayState()
  const [pending, setPending] = useState(false)
  const [feedback, setFeedback] = useState<RbacFeedbackState | null>(null)

  useEffect(() => setFeedback(null), [client.version])

  async function toggle() {
    setPending(true)
    try {
      const input = { id: client.id, expectedVersion: client.version }
      let result: Parameters<typeof mutationFeedback>[0]
      let changed: boolean
      if (client.enabled) {
        const disabled = await mutations.disable(input)
        result = disabled
        changed = Boolean(disabled.data?.disableClient)
      } else {
        const enabled = await mutations.enable(input)
        result = enabled
        changed = Boolean(enabled.data?.enableClient)
      }
      stateDialog.close()
      if (!changed) {
        setFeedback(mutationFeedback(result, 'missing_client_state_payload'))
        return
      }
      toast.success(t(client.enabled ? 'clientsDisabledToast' : 'clientsEnabledToast'))
    } finally {
      setPending(false)
    }
  }

  async function remove() {
    setPending(true)
    try {
      const result = await mutations.remove({
        id: client.id,
        expectedVersion: client.version,
      })
      deleteDialog.close()
      if (!result.data?.deleteClient) {
        setFeedback(mutationFeedback(result, 'missing_delete_client_payload'))
        return
      }
      toast.success(t('clientsDeletedToast'))
      void navigate({ to: '/clients', replace: true })
    } finally {
      setPending(false)
    }
  }

  return (
    <SettingsGroup title={t('clientsLifecycleTitle')} tone="danger">
      {feedback ? (
        <div className="px-5 py-4">
          <RbacMutationFeedback
            feedback={feedback}
            onReload={() => void query.refresh()}
            reloadPending={query.refreshing}
          />
        </div>
      ) : null}
      {scope.state ? (
        <SettingsRow
          label={t(client.enabled ? 'clientsDisableRow' : 'clientsEnableRow')}
          description={t(
            client.enabled ? 'clientsDisableDescription' : 'clientsEnableDescription',
          )}
          action={
            <Button variant="destructive" onClick={stateDialog.open}>
              <Power className="size-4" aria-hidden="true" />
              {t(client.enabled ? 'clientsDisable' : 'clientsEnable')}
            </Button>
          }
        />
      ) : null}
      {scope.delete ? (
        <SettingsRow
          label={t('clientsDeleteRow')}
          description={t('clientsDeleteRowHint')}
          action={
            <Button variant="destructive" onClick={deleteDialog.open}>
              <Trash2 className="size-4" aria-hidden="true" />
              {t('clientsDelete')}
            </Button>
          }
        />
      ) : null}
      <ConfirmationDialog
        state={stateDialog}
        title={t(client.enabled ? 'clientsDisableTitle' : 'clientsEnableTitle')}
        description={t(
          client.enabled ? 'clientsDisableDescription' : 'clientsEnableDescription',
        )}
        confirmLabel={t(client.enabled ? 'clientsDisable' : 'clientsEnable')}
        destructive={client.enabled}
        pending={pending}
        onConfirm={() => void toggle()}
      />
      <ConfirmationDialog
        state={deleteDialog}
        title={t('clientsDeleteTitle')}
        description={t('clientsDeleteDescription', {
          name: resolveLocalizedText(client.names, locale) ?? client.name,
        })}
        confirmLabel={t('clientsDelete')}
        destructive
        pending={pending}
        onConfirm={() => void remove()}
      />
    </SettingsGroup>
  )
}
