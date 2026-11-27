import { useId, useState } from 'react'

import { RbacMutationFeedback } from '#/components/rbac-feedback'
import {
  SettingsGroup,
  SettingsGroupSkeleton,
  SettingsNumberInput,
  SettingsRow,
} from '#/components/settings-section'
import { useTranslator, type MessageKey } from '#/lib/i18n'
import { rbacFieldErrors, type RbacFeedbackState } from '#/lib/rbac-errors'
import { toast } from '#/lib/toast'
import {
  useInstanceSettings,
  useSettingsBlocker,
  useSettingsDraft,
} from '../../settings/components/instance-settings-context'
import { SettingsFieldError, SettingsFormFooter } from '../../settings/components/settings-form-footer'
import { mutationFeedback, networkFeedback } from '../../settings/lib/feedback'
import type { FieldError } from '../../settings/lib/settings-form'
import { useEmailMutations } from '../hooks/email-mutations'
import {
  emailPolicyDraft,
  emailPolicyInput,
  emailPolicyRange,
  type EmailPolicy,
  type EmailPolicyDraft,
  type EmailPolicyNumberField,
} from '../lib/email-form'
import { useEmailScope } from '../lib/email-scope'

export function EmailPolicyPage() {
  const { settings } = useInstanceSettings()
  const blocked = useSettingsBlocker()
  if (blocked) return blocked
  if (!settings) {
    return (
      <div className="space-y-6" aria-busy="true">
        <SettingsGroupSkeleton rows={['control', 'control', 'control', 'control', 'control']} />
        <SettingsGroupSkeleton rows={['control', 'control', 'control', 'control']} />
      </div>
    )
  }
  return <EmailPolicyForm key={settings.email.policy.version} policy={settings.email.policy} />
}

function EmailPolicyForm({ policy }: { policy: EmailPolicy }) {
  const t = useTranslator()
  const { query } = useInstanceSettings()
  const scope = useEmailScope()
  const mutations = useEmailMutations()
  const errorPrefix = useId()
  const [draft, setDraft, resetDraft] = useSettingsDraft<EmailPolicyDraft>(
    'email_policy',
    policy.version,
    () => emailPolicyDraft(policy),
  )
  const [errors, setErrors] = useState<Partial<Record<EmailPolicyNumberField, FieldError>>>({})
  const [serverErrors, setServerErrors] = useState<Record<string, string>>({})
  const [feedback, setFeedback] = useState<RbacFeedbackState | null>(null)
  const [pending, setPending] = useState(false)
  const editable = scope.policyWrite
  const disabled = pending || !editable
  const dirty = JSON.stringify(draft) !== JSON.stringify(emailPolicyDraft(policy))

  function change(field: EmailPolicyNumberField, value: string) {
    setDraft((current) => ({ ...current, [field]: value }))
    setErrors((current) => ({ ...current, [field]: undefined }))
    setServerErrors({})
    setFeedback(null)
  }

  function errorFor(field: EmailPolicyNumberField): string | undefined {
    const local = errors[field]
    return local ? t(local.key, local.values) : serverErrors[field]
  }

  async function save() {
    if (pending || !dirty) return
    const prepared = emailPolicyInput(policy, draft)
    if ('errors' in prepared) {
      setErrors(prepared.errors)
      return
    }
    setPending(true)
    setFeedback(null)
    try {
      const result = await mutations.updatePolicy(prepared.input)
      if (!result.data?.updateEmailPolicySettings) {
        setServerErrors(rbacFieldErrors(result.errors))
        setFeedback(mutationFeedback(result, 'missing_update_email_policy_settings_payload'))
        return
      }
      toast.success(t('settingsSavedToast'))
    } catch {
      setFeedback(networkFeedback('email_policy_settings_request_failed'))
    } finally {
      setPending(false)
    }
  }

  const numberRow = (
    field: EmailPolicyNumberField,
    label: MessageKey,
    description: MessageKey,
    unit: MessageKey,
  ) => {
    const range = emailPolicyRange(policy, field)
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
        <SettingsGroup title={t('settingsEmailPolicyLifetimesSection')}>
          {numberRow(
            'signInCodeLifetimeMinutes',
            'settingsEmailPolicySignInCodeLifetime',
            'settingsEmailPolicySignInCodeLifetimeHint',
            'settingsUnitMinutes',
          )}
          {numberRow(
            'passwordResetLifetimeMinutes',
            'settingsEmailPolicyPasswordResetLifetime',
            'settingsEmailPolicyPasswordResetLifetimeHint',
            'settingsUnitMinutes',
          )}
          {numberRow(
            'registrationLifetimeMinutes',
            'settingsEmailPolicyRegistrationLifetime',
            'settingsEmailPolicyRegistrationLifetimeHint',
            'settingsUnitMinutes',
          )}
          {numberRow(
            'emailVerificationLifetimeHours',
            'settingsEmailPolicyVerificationLifetime',
            'settingsEmailPolicyVerificationLifetimeHint',
            'settingsUnitHours',
          )}
          {numberRow(
            'userInvitationLifetimeDays',
            'settingsEmailPolicyInvitationLifetime',
            'settingsEmailPolicyInvitationLifetimeHint',
            'settingsUnitDays',
          )}
        </SettingsGroup>

        <SettingsGroup title={t('settingsEmailPolicyLimitsSection')}>
          {numberRow(
            'resendIntervalSeconds',
            'settingsEmailPolicyResendInterval',
            'settingsEmailPolicyResendIntervalHint',
            'settingsUnitSeconds',
          )}
          {numberRow(
            'loginMaxSends',
            'settingsEmailPolicyLoginMaxSends',
            'settingsEmailPolicyLoginMaxSendsHint',
            'settingsUnitEmails',
          )}
          {numberRow(
            'verificationMaxSends',
            'settingsEmailPolicyVerificationMaxSends',
            'settingsEmailPolicyVerificationMaxSendsHint',
            'settingsUnitEmails',
          )}
          {numberRow(
            'verificationSendWindowHours',
            'settingsEmailPolicyVerificationSendWindow',
            'settingsEmailPolicyVerificationSendWindowHint',
            'settingsUnitHours',
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
            note={t('settingsEmailPolicyAppliesToNewEmails')}
          />
        ) : null}
      </form>
    </div>
  )
}
