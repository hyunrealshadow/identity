import {
  Alert,
  Button,
  Card,
  Spinner,
  toast,
  useOverlayState,
} from '@heroui/react'
import { useNavigate } from '@tanstack/react-router'
import { Power, Save, ShieldCheck, ShieldOff, Trash2 } from 'lucide-react'
import { useEffect, useMemo, useState } from 'react'

import { ConfirmationDialog } from '#/components/confirmation-dialog'
import { LocalizedTextField } from '#/components/localized-text-field'
import { SettingsGroup, SettingsRow } from '#/components/settings-section'
import type { UpdateClientInput } from '#/generated/graphql'
import { formatDateTime } from '#/lib/format'
import { useLocale, useTranslator, type MessageKey } from '#/lib/i18n'
import {
  createLocalizedDraft,
  hasLocalizedDraftChanges,
  localizedMetadata,
  type LocalizedDraft,
} from '#/lib/localized-values'
import { RbacMutationFeedback } from '#/modules/user-management/components/rbac-feedback'
import { resolveLocalizedText } from '#/modules/user-management/groups/lib/groups-search'
import type { RbacFeedbackState } from '#/modules/user-management/lib/rbac-errors'
import { useClientDetail, type ConsoleClient } from '../components/client-detail-shell'
import {
  CorsRow,
  GrantTypeRows,
  ParRow,
  RedirectUriRows,
  PublicClientFlowRow,
} from '../components/client-settings-fields'
import { useClientMutations } from '../hooks/client-mutations'
import {
  clientFieldErrors,
  formSeed,
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
  return <ClientOverview key={formSeed(client)} client={client} />
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
  const fieldProps = {
    draft: settings,
    onChange: (next: ClientSettingsDraft) => {
      setSettings(next)
      touched()
    },
    errors: errors.settings,
    isDisabled: pending || !editable,
  }

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
    <div className="space-y-8">
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
        className="space-y-6"
        onSubmit={(event) => {
          event.preventDefault()
          void save()
        }}
      >
        <SettingsGroup title={t('clientsBasicSection')}>
          <SettingsRow>
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
          </SettingsRow>
          <SettingsRow>
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
          </SettingsRow>
          <SettingsRow
            label={t('tableColumnCreated')}
            action={
              <span className="text-sm text-muted">
                {formatDateTime(client.createdAt, locale, timeZone)}
              </span>
            }
          />
          <SettingsRow
            label={t('clientsUpdated')}
            action={
              <span className="text-sm text-muted">
                {client.updatedAt
                  ? formatDateTime(client.updatedAt, locale, timeZone)
                  : t('clientsNeverUpdated')}
              </span>
            }
          />
        </SettingsGroup>

        <SettingsGroup title={t('clientsRedirectSection')}>
          <RedirectUriRows {...fieldProps} />
        </SettingsGroup>

        <SettingsGroup title={t('clientsCorsSection')}>
          <CorsRow {...fieldProps} />
          {client.corsEnabled ? (
            <SettingsRow
              label={t('clientsCorsOrigins')}
              description={t('clientsCorsOriginsHint')}
            >
              {client.corsOrigins.length ? (
                <ul className="flex flex-wrap gap-2">
                  {client.corsOrigins.map((origin) => (
                    <li key={origin}>
                      <code className="rounded-field bg-surface-secondary px-2 py-1 text-xs">
                        {origin}
                      </code>
                    </li>
                  ))}
                </ul>
              ) : (
                <p className="text-sm text-muted">{t('clientsCorsOriginsEmpty')}</p>
              )}
            </SettingsRow>
          ) : null}
        </SettingsGroup>

        <SettingsGroup title={t('clientsGrantTypes')}>
          <GrantTypeRows {...fieldProps} />
        </SettingsGroup>

        <SettingsGroup
          title={t('clientsPublicClientSection')}
          description={t('clientsPublicClientSectionHint')}
        >
          <PublicClientFlowRow {...fieldProps} />
        </SettingsGroup>

        <SettingsGroup title={t('clientsAuthorizationRequestsSection')}>
          <ParRow {...fieldProps} />
        </SettingsGroup>

        {editable ? (
          <div className="flex flex-wrap items-center justify-end gap-3">
            {settingsChanged ? (
              <span className="text-xs text-muted">{t('clientsSettingsWithdrawNote')}</span>
            ) : null}
            <Button type="submit" isDisabled={pending || !dirty}>
              {pending ? (
                <Spinner size="sm" aria-label={t('clientsSavePending')} />
              ) : (
                <Save className="size-4" aria-hidden="true" />
              )}
              {t('clientsSave')}
            </Button>
          </div>
        ) : null}
      </form>

      {!client.builtIn && (scope.state || scope.delete || scope.update) ? (
        <ClientLifecycle client={client} />
      ) : null}
    </div>
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
  const consentDialog = useOverlayState()
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
    } finally {
      setPending(false)
    }
  }

  async function setSkipConsent(skipConsent: boolean) {
    setPending(true)
    try {
      const result = await mutations.update({
        id: client.id,
        expectedVersion: client.version,
        settings: settingsInput({ ...settingsDraftFromClient(client), skipConsent }),
      })
      consentDialog.close()
      if (!result.data?.updateClient) {
        setFeedback(feedbackFrom(result, 'missing_update_client_payload'))
        return
      }
      toast.success(t('clientsSavedToast'), { description: t('clientsSavedWithdrawn') })
    } catch {
      consentDialog.close()
      setFeedback({
        errors: [],
        failure: { kind: 'network', code: 'client_update_request_failed' },
        forbidden: false,
      })
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
    <SettingsGroup title={t('clientsLifecycleTitle')} tone="danger">
      {feedback ? (
        <div className="px-4 py-3">
          <RbacMutationFeedback
            feedback={feedback}
            onReload={() => void query.refresh()}
            reloadPending={query.refreshing}
          />
        </div>
      ) : null}
      {scope.update ? (
        <SettingsRow
          label={t('clientsSkipConsent')}
          description={t(
            client.skipConsent ? 'clientsSkipConsentOnHint' : 'clientsSkipConsentHint',
          )}
          action={
            client.skipConsent ? (
              <Button
                variant="danger-soft"
                isDisabled={pending}
                onPress={() => void setSkipConsent(false)}
              >
                <ShieldCheck className="size-4" aria-hidden="true" />
                {t('clientsSkipConsentDisable')}
              </Button>
            ) : (
              <Button variant="danger-soft" onPress={consentDialog.open}>
                <ShieldOff className="size-4" aria-hidden="true" />
                {t('clientsSkipConsentEnable')}
              </Button>
            )
          }
        />
      ) : null}
      {scope.state ? (
        <SettingsRow
          label={t(client.enabled ? 'clientsDisableRow' : 'clientsEnableRow')}
          description={t(
            client.enabled ? 'clientsDisableDescription' : 'clientsEnableDescription',
          )}
          action={
            <Button variant="danger-soft" onPress={stateDialog.open}>
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
            <Button variant="danger" onPress={deleteDialog.open}>
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
        state={consentDialog}
        title={t('clientsSkipConsentConfirmTitle')}
        description={t('clientsSkipConsentConfirmDescription')}
        confirmLabel={t('clientsSkipConsentEnable')}
        destructive
        pending={pending}
        onConfirm={() => void setSkipConsent(true)}
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
