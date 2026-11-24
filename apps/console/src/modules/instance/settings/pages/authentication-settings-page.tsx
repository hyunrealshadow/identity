import { Link } from '@tanstack/react-router'
import { useId, useState } from 'react'

import {
  SettingsGroup,
  SettingsGroupSkeleton,
  SettingsNumberInput,
  SettingsRow,
  SettingsSwitch,
} from '#/components/settings-section'
import { useTranslator, type MessageKey } from '#/lib/i18n'
import { toast } from '#/lib/toast'
import { RbacMutationFeedback } from '#/modules/user-management/components/rbac-feedback'
import { rbacFieldErrors, type RbacFeedbackState } from '#/modules/user-management/lib/rbac-errors'
import { SettingsFieldError, SettingsFormFooter } from '../components/settings-form-footer'
import {
  useInstanceSettings,
  useSettingsBlocker,
  useSettingsDraft,
} from '../components/instance-settings-context'
import { useSettingMutations } from '../hooks/setting-mutations'
import { mutationFeedback, networkFeedback } from '../lib/feedback'
import {
  authenticationDraft,
  authenticationInput,
  hashingRange,
  type AuthenticationDraft,
  type AuthenticationSettings,
  type FieldError,
  type HashingField,
} from '../lib/settings-form'

export function AuthenticationSettingsPage() {
  const { settings } = useInstanceSettings()
  const blocked = useSettingsBlocker()
  if (blocked) return blocked
  if (!settings) {
    return (
      <div className="space-y-6" aria-busy="true">
        <SettingsGroupSkeleton rows={['switch', 'switch']} />
        <SettingsGroupSkeleton rows={['control', 'control', 'control']} description />
      </div>
    )
  }
  return (
    <AuthenticationSettingsForm
      key={settings.authentication.version}
      settings={settings.authentication}
    />
  )
}

function AuthenticationSettingsForm({ settings }: { settings: AuthenticationSettings }) {
  const t = useTranslator()
  const { scope, query, settings: instance } = useInstanceSettings()
  const deliveryConfigured = instance?.email.delivery.configured ?? false
  const mutations = useSettingMutations()
  const errorPrefix = useId()
  const [draft, setDraft, resetDraft] = useSettingsDraft<AuthenticationDraft>(
    'authentication',
    settings.version,
    () => authenticationDraft(settings),
  )
  const [errors, setErrors] = useState<Partial<Record<HashingField, FieldError>>>({})
  const [serverErrors, setServerErrors] = useState<Record<string, string>>({})
  const [feedback, setFeedback] = useState<RbacFeedbackState | null>(null)
  const [pending, setPending] = useState(false)
  const editable = scope.authenticationWrite
  const disabled = pending || !editable
  const dirty = JSON.stringify(draft) !== JSON.stringify(authenticationDraft(settings))

  function change<K extends keyof AuthenticationDraft>(field: K, value: AuthenticationDraft[K]) {
    setDraft((current) => ({ ...current, [field]: value }))
    setErrors((current) => ({ ...current, [field]: undefined }))
    setServerErrors({})
    setFeedback(null)
  }

  async function save() {
    if (pending || !dirty) return
    const prepared = authenticationInput(settings, draft)
    if ('errors' in prepared) {
      setErrors(prepared.errors)
      return
    }
    setPending(true)
    setFeedback(null)
    try {
      const result = await mutations.updateAuthentication(prepared.input)
      if (!result.data?.updateAuthenticationSettings) {
        setServerErrors(rbacFieldErrors(result.errors))
        setFeedback(mutationFeedback(result, 'missing_update_authentication_settings_payload'))
        return
      }
      toast.success(t('settingsSavedToast'))
    } catch {
      setFeedback(networkFeedback('authentication_settings_request_failed'))
    } finally {
      setPending(false)
    }
  }

  const hashingRow = (
    field: HashingField,
    label: MessageKey,
    description: MessageKey,
    unit?: MessageKey,
  ) => {
    const range = hashingRange(settings, field)
    const local = errors[field]
    const message = local ? t(local.key, local.values) : serverErrors[field]
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
            unit={unit ? t(unit) : undefined}
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
        <SettingsGroup title={t('settingsSignInSection')}>
          <SettingsRow
            label={t('settingsIdentifierEnumeration')}
            description={t('settingsIdentifierEnumerationHint')}
            action={
              <SettingsSwitch
                label={t('settingsIdentifierEnumeration')}
                isSelected={draft.identifierEnumerationAllowed}
                onChange={(value) => change('identifierEnumerationAllowed', value)}
                isDisabled={disabled}
              />
            }
          />
          <SettingsRow
            label={t('settingsEmailSignIn')}
            description={t('settingsEmailSignInHint')}
            action={
              <SettingsSwitch
                label={t('settingsEmailSignIn')}
                isSelected={draft.emailSignInEnabled}
                onChange={(value) => change('emailSignInEnabled', value)}
                isDisabled={disabled || (!deliveryConfigured && !draft.emailSignInEnabled)}
              />
            }
          >
            {!deliveryConfigured ? (
              <p className="text-xs leading-5 text-muted-foreground">
                {t(
                  draft.emailSignInEnabled
                    ? 'settingsEmailSignInDeliveryOff'
                    : 'settingsEmailSignInNeedsDelivery',
                )}{' '}
                <Link to="/email" className="text-link">
                  {t('settingsEmailSignInConfigureDelivery')}
                </Link>
              </p>
            ) : null}
            {serverErrors.emailSignInEnabled ? (
              <SettingsFieldError
                id={`${errorPrefix}-emailSignInEnabled`}
                message={serverErrors.emailSignInEnabled}
              />
            ) : null}
          </SettingsRow>
          <SettingsRow
            label={t('settingsPasswordReset')}
            description={t('settingsPasswordResetHint')}
            action={
              <SettingsSwitch
                label={t('settingsPasswordReset')}
                isSelected={draft.passwordResetEnabled}
                onChange={(value) => change('passwordResetEnabled', value)}
                isDisabled={disabled || (!deliveryConfigured && !draft.passwordResetEnabled)}
              />
            }
          >
            {!deliveryConfigured ? (
              <p className="text-xs leading-5 text-muted-foreground">
                {t(
                  draft.passwordResetEnabled
                    ? 'settingsPasswordResetDeliveryOff'
                    : 'settingsPasswordResetNeedsDelivery',
                )}{' '}
                <Link to="/email" className="text-link">
                  {t('settingsEmailSignInConfigureDelivery')}
                </Link>
              </p>
            ) : null}
            {serverErrors.passwordResetEnabled ? (
              <SettingsFieldError
                id={`${errorPrefix}-passwordResetEnabled`}
                message={serverErrors.passwordResetEnabled}
              />
            ) : null}
          </SettingsRow>
        </SettingsGroup>

        <SettingsGroup title={t('settingsPasswordPolicySection')}>
          <SettingsRow
            label={t('settingsBreachedPasswordCheck')}
            description={t('settingsBreachedPasswordCheckHint')}
            action={
              <SettingsSwitch
                label={t('settingsBreachedPasswordCheck')}
                isSelected={draft.breachedPasswordCheckEnabled}
                onChange={(value) => change('breachedPasswordCheckEnabled', value)}
                isDisabled={disabled}
              />
            }
          />
          {hashingRow(
            'passwordMaxAgeDays',
            'settingsPasswordMaxAge',
            'settingsPasswordMaxAgeHint',
            'settingsUnitDays',
          )}
          {hashingRow(
            'passwordHistoryCount',
            'settingsPasswordHistory',
            'settingsPasswordHistoryHint',
          )}
        </SettingsGroup>

        <SettingsGroup
          title={t('settingsHashingSection')}
          description={t('settingsHashingSectionHint')}
        >
          {hashingRow('timeCost', 'settingsHashingTimeCost', 'settingsHashingTimeCostHint')}
          {hashingRow(
            'memoryCostKib',
            'settingsHashingMemoryCost',
            'settingsHashingMemoryCostHint',
            'settingsUnitKib',
          )}
          {hashingRow(
            'parallelism',
            'settingsHashingParallelism',
            'settingsHashingParallelismHint',
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
            note={t('settingsHashingAppliesLater')}
          />
        ) : null}
      </form>
    </div>
  )
}
