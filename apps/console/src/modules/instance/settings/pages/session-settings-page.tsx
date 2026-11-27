import { useId, useState } from 'react'

import {
  SettingsGroup,
  SettingsGroupSkeleton,
  SettingsNumberInput,
  SettingsRow,
} from '#/components/settings-section'
import { useTranslator, type MessageKey } from '#/lib/i18n'
import { toast } from '#/lib/toast'
import { RbacMutationFeedback } from '#/components/rbac-feedback'
import { rbacFieldErrors, type RbacFeedbackState } from '#/lib/rbac-errors'
import { SettingsFieldError, SettingsFormFooter } from '../components/settings-form-footer'
import {
  useInstanceSettings,
  useSettingsBlocker,
  useSettingsDraft,
} from '../components/instance-settings-context'
import { useSettingMutations } from '../hooks/setting-mutations'
import { mutationFeedback, networkFeedback } from '../lib/feedback'
import {
  sessionDraft,
  sessionInput,
  sessionRange,
  type FieldError,
  type SessionDraft,
  type SessionNumberField,
  type SessionSettings,
} from '../lib/settings-form'

export function SessionSettingsPage() {
  const { settings } = useInstanceSettings()
  const blocked = useSettingsBlocker()
  if (blocked) return blocked
  if (!settings) {
    return (
      <div className="space-y-6" aria-busy="true">
        <SettingsGroupSkeleton rows={['control']} />
        <SettingsGroupSkeleton rows={['control', 'control', 'control']} />
      </div>
    )
  }
  return <SessionSettingsForm key={settings.session.version} settings={settings.session} />
}

function SessionSettingsForm({ settings }: { settings: SessionSettings }) {
  const t = useTranslator()
  const { scope, query } = useInstanceSettings()
  const mutations = useSettingMutations()
  const errorPrefix = useId()
  const [draft, setDraft, resetDraft] = useSettingsDraft<SessionDraft>(
    'session',
    settings.version,
    () => sessionDraft(settings),
  )
  const [errors, setErrors] = useState<Partial<Record<SessionNumberField, FieldError>>>({})
  const [serverErrors, setServerErrors] = useState<Record<string, string>>({})
  const [feedback, setFeedback] = useState<RbacFeedbackState | null>(null)
  const [pending, setPending] = useState(false)
  const editable = scope.sessionWrite
  const disabled = pending || !editable
  const dirty = JSON.stringify(draft) !== JSON.stringify(sessionDraft(settings))

  function change<K extends keyof SessionDraft>(field: K, value: SessionDraft[K]) {
    setDraft((current) => ({ ...current, [field]: value }))
    setErrors((current) => ({ ...current, [field]: undefined }))
    setServerErrors({})
    setFeedback(null)
  }

  function errorFor(field: SessionNumberField): string | undefined {
    const local = errors[field]
    return local ? t(local.key, local.values) : serverErrors[field]
  }

  async function save() {
    if (pending || !dirty) return
    const prepared = sessionInput(settings, draft)
    if ('errors' in prepared) {
      setErrors(prepared.errors)
      return
    }
    setPending(true)
    setFeedback(null)
    try {
      const result = await mutations.updateSession(prepared.input)
      if (!result.data?.updateSessionSettings) {
        setServerErrors(rbacFieldErrors(result.errors))
        setFeedback(mutationFeedback(result, 'missing_update_session_settings_payload'))
        return
      }
      toast.success(t('settingsSavedToast'))
    } catch {
      setFeedback(networkFeedback('session_settings_request_failed'))
    } finally {
      setPending(false)
    }
  }

  const numberRow = (
    field: SessionNumberField,
    label: MessageKey,
    description: MessageKey,
    unit: MessageKey,
  ) => {
    const range = sessionRange(settings, field)
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
            unit={t(unit)}
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
        <SettingsGroup title={t('settingsSessionSection')}>
          {numberRow(
            'sessionLifetimeHours',
            'settingsSessionLifetime',
            'settingsSessionLifetimeHint',
            'settingsUnitHours',
          )}
        </SettingsGroup>

        <SettingsGroup title={t('settingsFreshnessSection')}>
          {numberRow(
            'elevatedAuthenticationLifetimeMinutes',
            'settingsElevatedAuthenticationLifetime',
            'settingsElevatedAuthenticationLifetimeHint',
            'settingsUnitMinutes',
          )}
          {numberRow(
            'recentAuthenticationLifetimeMinutes',
            'settingsRecentAuthenticationLifetime',
            'settingsRecentAuthenticationLifetimeHint',
            'settingsUnitMinutes',
          )}
          {numberRow(
            'loginLifetimeMinutes',
            'settingsLoginLifetime',
            'settingsLoginLifetimeHint',
            'settingsUnitMinutes',
          )}
        </SettingsGroup>

        {editable ? (
          <SettingsFormFooter
            dirty={dirty}
            pending={pending}
            onDiscard={() => {
              resetDraft()
              setErrors({})
              setServerErrors({})
              setFeedback(null)
            }}
            note={t('settingsSessionAppliesToNewSessions')}
          />
        ) : null}
      </form>
    </div>
  )
}
