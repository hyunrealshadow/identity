import { useId, useState } from 'react'

import {
  SettingsGroup,
  SettingsGroupSkeleton,
  SettingsNumberInput,
  SettingsRow,
  SettingsSelect,
  SettingsSwitch,
} from '#/components/settings-section'
import type { ClientOAuthVersion } from '#/generated/graphql'
import { useTranslator, type MessageKey } from '#/lib/i18n'
import { toast } from '#/lib/toast'
import { RbacMutationFeedback } from '#/modules/user-management/components/rbac-feedback'
import { rbacFieldErrors, type RbacFeedbackState } from '#/modules/user-management/lib/rbac-errors'
import { SettingsFieldError, SettingsFormFooter } from '../components/settings-form-footer'
import { useInstanceSettings, useSettingsBlocker } from '../components/settings-shell'
import { useSettingMutations } from '../hooks/setting-mutations'
import { mutationFeedback, networkFeedback } from '../lib/feedback'
import {
  protocolDraft,
  protocolInput,
  protocolRange,
  type FieldError,
  type ProtocolDraft,
  type ProtocolNumberField,
  type ProtocolSettings,
} from '../lib/settings-form'

export function ProtocolSettingsPage() {
  const { settings } = useInstanceSettings()
  const blocked = useSettingsBlocker()
  if (blocked) return blocked
  if (!settings) {
    return (
      <div className="space-y-6" aria-busy="true">
        <SettingsGroupSkeleton rows={['control']} description />
        <SettingsGroupSkeleton rows={['switch', 'control']} />
        <SettingsGroupSkeleton rows={['control', 'control']} />
        <SettingsGroupSkeleton rows={['switch']} />
      </div>
    )
  }
  // A new server version resets the draft to what was saved.
  return <ProtocolSettingsForm key={settings.protocol.version} settings={settings.protocol} />
}

function ProtocolSettingsForm({ settings }: { settings: ProtocolSettings }) {
  const t = useTranslator()
  const { scope, query } = useInstanceSettings()
  const mutations = useSettingMutations()
  const errorPrefix = useId()
  const [draft, setDraft] = useState<ProtocolDraft>(() => protocolDraft(settings))
  const [errors, setErrors] = useState<Partial<Record<ProtocolNumberField, FieldError>>>({})
  const [serverErrors, setServerErrors] = useState<Record<string, string>>({})
  const [feedback, setFeedback] = useState<RbacFeedbackState | null>(null)
  const [pending, setPending] = useState(false)
  const editable = scope.protocolWrite
  const disabled = pending || !editable
  const dirty = JSON.stringify(draft) !== JSON.stringify(protocolDraft(settings))

  function change<K extends keyof ProtocolDraft>(field: K, value: ProtocolDraft[K]) {
    setDraft((current) => ({ ...current, [field]: value }))
    setErrors((current) => ({ ...current, [field]: undefined }))
    setServerErrors({})
    setFeedback(null)
  }

  function errorFor(field: ProtocolNumberField): string | undefined {
    const local = errors[field]
    return local ? t(local.key, local.values) : serverErrors[field]
  }

  async function save() {
    if (pending || !dirty) return
    const prepared = protocolInput(settings, draft)
    if ('errors' in prepared) {
      setErrors(prepared.errors)
      return
    }
    setPending(true)
    setFeedback(null)
    try {
      const result = await mutations.updateProtocol(prepared.input)
      if (!result.data?.updateProtocolSettings) {
        setServerErrors(rbacFieldErrors(result.errors))
        setFeedback(mutationFeedback(result, 'missing_update_protocol_settings_payload'))
        return
      }
      toast.success(t('settingsSavedToast'))
    } catch {
      setFeedback(networkFeedback('protocol_settings_request_failed'))
    } finally {
      setPending(false)
    }
  }

  const numberRow = (
    field: ProtocolNumberField,
    label: MessageKey,
    description: MessageKey,
  ) => {
    const range = protocolRange(settings, field)
    const message = errorFor(field)
    const errorId = `${errorPrefix}-${field}`
    return (
      <SettingsRow
        label={t(label)}
        description={t(description, { min: range.min, max: range.max })}
        action={
          <SettingsNumberInput
            name={field}
            label={t(label)}
            value={draft[field]}
            onChange={(value) => change(field, value)}
            min={range.min}
            max={range.max}
            unit={t('settingsUnitSeconds')}
            invalid={Boolean(message)}
            errorId={errorId}
            isDisabled={disabled}
          />
        }
      >
        {message ? <SettingsFieldError id={errorId} message={message} /> : null}
      </SettingsRow>
    )
  }

  return (
    <div className="space-y-6">
      {feedback ? (
        <RbacMutationFeedback
          feedback={feedback}
          onReload={() => void query.refresh()}
          reloadPending={query.refreshing}
          conflictTitleKey="settingsConflictTitle"
          conflictDescriptionKey="settingsConflictDescription"
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
        <SettingsGroup
          title={t('settingsOAuthSection')}
          description={t('settingsOAuthSectionHint')}
        >
          <SettingsRow
            label={t('settingsOAuthVersion')}
            description={t('settingsOAuthVersionHint')}
            action={
              <SettingsSelect
                label={t('settingsOAuthVersion')}
                value={draft.oauthVersion}
                onChange={(value) => change('oauthVersion', value as ClientOAuthVersion)}
                options={[
                  { id: 'OAUTH_2_0', label: 'OAuth 2.0' },
                  { id: 'OAUTH_2_1', label: 'OAuth 2.1' },
                ]}
                isDisabled={disabled}
              />
            }
          />
        </SettingsGroup>

        <SettingsGroup title={t('settingsParSection')}>
          <SettingsRow
            label={t('settingsRequirePar')}
            description={t('settingsRequireParHint')}
            action={
              <SettingsSwitch
                label={t('settingsRequirePar')}
                isSelected={draft.requirePushedAuthorizationRequests}
                onChange={(value) => change('requirePushedAuthorizationRequests', value)}
                isDisabled={disabled}
              />
            }
          />
          {numberRow(
            'pushedAuthorizationRequestLifetimeSeconds',
            'settingsParLifetime',
            'settingsParLifetimeHint',
          )}
        </SettingsGroup>

        <SettingsGroup title={t('settingsDeviceSection')}>
          {numberRow(
            'deviceAuthorizationRequestLifetimeSeconds',
            'settingsDeviceLifetime',
            'settingsDeviceLifetimeHint',
          )}
          {numberRow(
            'deviceAuthorizationPollingIntervalSeconds',
            'settingsDeviceInterval',
            'settingsDeviceIntervalHint',
          )}
        </SettingsGroup>

        <SettingsGroup title={t('settingsRegistrationSection')}>
          <SettingsRow
            label={t('settingsDynamicRegistration')}
            description={t('settingsDynamicRegistrationHint')}
            action={
              <SettingsSwitch
                label={t('settingsDynamicRegistration')}
                isSelected={draft.dynamicRegistrationEnabled}
                onChange={(value) => change('dynamicRegistrationEnabled', value)}
                isDisabled={disabled}
              />
            }
          />
        </SettingsGroup>

        {editable ? (
          <SettingsFormFooter
            dirty={dirty}
            pending={pending}
            onDiscard={() => {
              setDraft(protocolDraft(settings))
              setErrors({})
              setServerErrors({})
              setFeedback(null)
            }}
            note={t('settingsAppliesToNewRequests')}
          />
        ) : null}
      </form>
    </div>
  )
}
