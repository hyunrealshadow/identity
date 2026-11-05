import {
  Alert,
  Button,
  Card,
  Spinner,
  toast,
  useOverlayState,
} from '@heroui/react'
import { useNavigate } from '@tanstack/react-router'
import { Power, Save, Trash2 } from 'lucide-react'
import { useEffect, useMemo, useState } from 'react'

import { ConfirmationDialog } from '#/components/confirmation-dialog'
import { LocalizedTextField } from '#/components/localized-text-field'
import type { UpdateClientInput } from '#/gql/graphql'
import { formatDateTime } from '#/lib/format'
import { useLocale, useTranslator, type MessageKey } from '#/lib/i18n'
import {
  createLocalizedDraft,
  hasLocalizedDraftChanges,
  localizedMetadata,
  type LocalizedDraft,
} from '#/lib/localized-values'
import { RbacMutationFeedback } from '#/modules/user-management/components/rbac-feedback'
import type { RbacFeedbackState } from '#/modules/user-management/lib/rbac-errors'
import { useClientDetail, type ConsoleClient } from '../components/client-detail-shell'
import { ClientSettingsFields } from '../components/client-settings-fields'
import { useClientMutations } from '../hooks/client-mutations'
import {
  clientFieldErrors,
  settingsDraftFromClient,
  settingsInput,
  validateSettings,
  type ClientFieldErrors,
  type ClientSettingsDraft,
} from '../lib/client-form'

const noErrors: ClientFieldErrors = { settings: {}, text: {} }

interface MutationResultLike {
  errors: RbacFeedbackState['errors']
  failure?: RbacFeedbackState['failure']
  stepUp?: RbacFeedbackState['stepUp']
  requestId?: string
  traceId?: string
  forbidden: boolean
}

function feedbackFrom(result: MutationResultLike, code: string): RbacFeedbackState {
  return {
    errors: result.errors,
    failure: result.failure ?? {
      kind: 'invalid_response',
      code,
      requestId: result.requestId,
      traceId: result.traceId,
    },
    stepUp: result.stepUp,
    requestId: result.requestId,
    traceId: result.traceId,
    forbidden: result.forbidden,
  }
}

export function ClientDetailPage() {
  const { client } = useClientDetail()
  if (!client) return <ClientDetailSkeleton />
  // Re-seed the form whenever the server version changes.
  return <ClientOverview key={client.version} client={client} />
}

function ClientDetailSkeleton() {
  return (
    <div className="space-y-4" aria-busy="true">
      {[0, 1].map((index) => (
        <Card key={index} className="console-card border border-border">
          <Card.Content className="space-y-3 p-5">
            <div className="h-4 w-40 animate-pulse rounded-field bg-surface-secondary" />
            <div className="h-10 w-full animate-pulse rounded-field bg-surface-secondary" />
            <div className="h-10 w-full animate-pulse rounded-field bg-surface-secondary" />
          </Card.Content>
        </Card>
      ))}
    </div>
  )
}

function Fact({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div>
      <dt className="text-xs font-medium text-muted">{label}</dt>
      <dd className="mt-0.5 break-all text-sm">{children}</dd>
    </div>
  )
}

function ClientOverview({ client }: { client: ConsoleClient }) {
  const t = useTranslator()
  const { locale, timeZone } = useLocale()
  const { query, scope } = useClientDetail()
  const mutations = useClientMutations()
  const [text, setText] = useState<LocalizedDraft>(() => createLocalizedDraft(client))
  const [settings, setSettings] = useState<ClientSettingsDraft>(() =>
    settingsDraftFromClient(client),
  )
  const [errors, setErrors] = useState<ClientFieldErrors>(noErrors)
  const [nameError, setNameError] = useState<MessageKey | null>(null)
  const [feedback, setFeedback] = useState<RbacFeedbackState | null>(null)
  const [pending, setPending] = useState(false)

  const editable = scope.update && !client.builtIn
  const original = useMemo(
    () => JSON.stringify(settingsInput(settingsDraftFromClient(client))),
    [client],
  )
  const settingsChanged = JSON.stringify(settingsInput(settings)) !== original
  const textChanged = hasLocalizedDraftChanges(client, text)
  const dirty = settingsChanged || textChanged

  function touched() {
    setFeedback(null)
    setErrors(noErrors)
    setNameError(null)
  }

  async function save() {
    if (pending || !dirty) return
    const local = settingsChanged ? validateSettings(settings) : {}
    const missingName = text.name.trim() === ''
    if (missingName || Object.keys(local).length > 0) {
      setNameError(missingName ? 'clientsNameRequired' : null)
      setErrors({
        settings: Object.fromEntries(
          Object.entries(local).map(([field, key]) => [field, t(key)]),
        ),
        text: {},
      })
      return
    }
    setPending(true)
    setFeedback(null)
    try {
      const input: UpdateClientInput = {
        id: client.id,
        expectedVersion: client.version,
      }
      if (textChanged) Object.assign(input, localizedMetadata(text))
      if (settingsChanged) input.settings = settingsInput(settings)
      const result = await mutations.update(input)
      if (!result.data?.updateClient) {
        setErrors(clientFieldErrors(result.errors))
        setFeedback(feedbackFrom(result, 'missing_update_client_payload'))
        return
      }
      toast.success(t('clientsSavedToast'), {
        description: t(settingsChanged ? 'clientsSavedWithdrawn' : 'clientsSavedCommitted'),
      })
      void query.refresh()
    } catch {
      setFeedback({
        errors: [],
        failure: { kind: 'network', code: 'client_update_request_failed' },
        forbidden: false,
      })
    } finally {
      setPending(false)
    }
  }

  return (
    <div className="space-y-4">
      {client.builtIn ? (
        <Alert status="default">
          <Alert.Indicator />
          <Alert.Content>
            <Alert.Title>{t('clientsBuiltInTitle')}</Alert.Title>
            <Alert.Description>{t('clientsBuiltInDescription')}</Alert.Description>
          </Alert.Content>
        </Alert>
      ) : null}
      {!client.enabled ? (
        <Alert status="warning">
          <Alert.Indicator />
          <Alert.Content>
            <Alert.Title>{t('clientsDisabledTitle')}</Alert.Title>
            <Alert.Description>{t('clientsDisabledDescription')}</Alert.Description>
          </Alert.Content>
        </Alert>
      ) : null}

      <Card className="console-card border border-border">
        <Card.Content className="p-5">
          <dl className="grid gap-4 sm:grid-cols-3">
            <Fact label={t('clientsClientId')}>
              <code className="text-xs">{client.clientId}</code>
            </Fact>
            <Fact label={t('tableColumnCreated')}>
              {formatDateTime(client.createdAt, locale, timeZone)}
            </Fact>
            <Fact label={t('clientsUpdated')}>
              {client.updatedAt
                ? formatDateTime(client.updatedAt, locale, timeZone)
                : t('clientsNeverUpdated')}
            </Fact>
            {client.corsEnabled ? (
              <div className="sm:col-span-3">
                <Fact label={t('clientsCorsOrigins')}>
                  {client.corsOrigins.length ? (
                    <ul className="space-y-0.5">
                      {client.corsOrigins.map((origin) => (
                        <li key={origin}>
                          <code className="text-xs">{origin}</code>
                        </li>
                      ))}
                    </ul>
                  ) : (
                    <span className="text-muted">{t('clientsCorsOriginsEmpty')}</span>
                  )}
                </Fact>
              </div>
            ) : null}
          </dl>
        </Card.Content>
      </Card>

      {feedback ? (
        <RbacMutationFeedback
          feedback={feedback}
          onReload={() => void query.refresh()}
          reloadPending={query.refreshing}
        />
      ) : null}

      <form
        noValidate
        aria-busy={pending}
        className="space-y-4"
        onSubmit={(event) => {
          event.preventDefault()
          void save()
        }}
      >
        <Card className="console-card border border-border">
          <Card.Content className="space-y-6 p-5">
            <LocalizedTextField
              name="names"
              label={t('localizedName')}
              defaultValue={text.name}
              onDefaultValueChange={(name) => {
                setText({ ...text, name })
                touched()
              }}
              value={text.names}
              onChange={(names) => {
                setText({ ...text, names })
                touched()
              }}
              isDisabled={pending || !editable}
              isRequired
              maxLength={256}
              error={nameError ? t(nameError) : (errors.text.name ?? errors.text.names)}
            />
            <LocalizedTextField
              name="descriptions"
              label={t('localizedDescription')}
              defaultValue={text.description}
              onDefaultValueChange={(description) => {
                setText({ ...text, description })
                touched()
              }}
              value={text.descriptions}
              onChange={(descriptions) => {
                setText({ ...text, descriptions })
                touched()
              }}
              isDisabled={pending || !editable}
              multiline
              maxLength={1024}
              error={errors.text.description ?? errors.text.descriptions}
            />
          </Card.Content>
        </Card>
        <Card className="console-card border border-border">
          <Card.Content className="p-5">
            <ClientSettingsFields
              draft={settings}
              onChange={(next) => {
                setSettings(next)
                touched()
              }}
              errors={errors.settings}
              isDisabled={pending || !editable}
            />
          </Card.Content>
        </Card>
        {editable ? (
          <div className="flex flex-wrap items-center gap-3">
            <Button type="submit" isDisabled={pending || !dirty}>
              {pending ? (
                <Spinner size="sm" aria-label={t('clientsSavePending')} />
              ) : (
                <Save className="size-4" aria-hidden="true" />
              )}
              {t('clientsSave')}
            </Button>
            {settingsChanged ? (
              <span className="text-xs text-muted">{t('clientsSettingsWithdrawNote')}</span>
            ) : null}
          </div>
        ) : null}
      </form>

      {!client.builtIn && (scope.state || scope.delete) ? (
        <ClientLifecycle client={client} />
      ) : null}
    </div>
  )
}

function ClientLifecycle({ client }: { client: ConsoleClient }) {
  const t = useTranslator()
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
      let result: MutationResultLike
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
      if (!changed) {
        setFeedback(feedbackFrom(result, 'missing_client_state_payload'))
        stateDialog.close()
        return
      }
      stateDialog.close()
      toast.success(t(client.enabled ? 'clientsDisabledToast' : 'clientsEnabledToast'))
      void query.refresh()
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
      if (!result.data?.deleteClient) {
        setFeedback(feedbackFrom(result, 'missing_delete_client_payload'))
        deleteDialog.close()
        return
      }
      deleteDialog.close()
      toast.success(t('clientsDeletedToast'))
      void navigate({ to: '/clients', replace: true })
    } finally {
      setPending(false)
    }
  }

  return (
    <Card className="console-card border border-border">
      <Card.Content className="space-y-4 p-5">
        <div>
          <h3 className="text-sm font-semibold">{t('clientsLifecycleTitle')}</h3>
          <p className="mt-1 text-sm text-muted">{t('clientsLifecycleDescription')}</p>
        </div>
        {feedback ? (
          <RbacMutationFeedback
            feedback={feedback}
            onReload={() => void query.refresh()}
            reloadPending={query.refreshing}
          />
        ) : null}
        <div className="flex flex-wrap gap-2">
          {scope.state ? (
            <Button variant="secondary" onPress={stateDialog.open}>
              <Power className="size-4" aria-hidden="true" />
              {t(client.enabled ? 'clientsDisable' : 'clientsEnable')}
            </Button>
          ) : null}
          {scope.delete ? (
            <Button variant="danger" onPress={deleteDialog.open}>
              <Trash2 className="size-4" aria-hidden="true" />
              {t('clientsDelete')}
            </Button>
          ) : null}
        </div>
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
          description={t('clientsDeleteDescription', { name: client.name })}
          confirmLabel={t('clientsDelete')}
          destructive
          pending={pending}
          onConfirm={() => void remove()}
        />
      </Card.Content>
    </Card>
  )
}
