import { Button } from '@identity/ui/components/button'
import { Input } from '@identity/ui/components/input'
import { useOverlayState } from '@identity/ui/hooks/use-overlay-state'
import { Send } from 'lucide-react'
import { useId, useState } from 'react'

import {
  SettingsGroup,
  SettingsGroupSkeleton,
  SettingsNumberInput,
  SettingsRow,
  SettingsSelect,
  SettingsSwitch,
} from '#/components/settings-section'
import { fieldErrorMap } from '#/lib/graphql/transport'
import { useTranslator, type MessageKey } from '#/lib/i18n'
import { toast } from '#/lib/toast'
import { RbacMutationFeedback } from '#/modules/user-management/components/rbac-feedback'
import type { RbacFeedbackState } from '#/modules/user-management/lib/rbac-errors'
import { SettingsFieldError, SettingsFormFooter } from '../../settings/components/settings-form-footer'
import {
  useInstanceSettings,
  useSettingsBlocker,
  useSettingsDraft,
} from '../../settings/components/instance-settings-context'
import { SendTestEmailDialog } from '../components/send-test-email-dialog'
import { useEmailMutations } from '../hooks/email-mutations'
import { useEmailScope } from '../lib/email-scope'
import {
  SMTP_DEFAULT_PORTS,
  emailDeliveryDirty,
  emailDeliveryDraft,
  emailDeliveryInput,
  storedSecret,
  type EmailDelivery,
  type EmailDeliveryDraft,
  type EmailDeliveryField,
} from '../lib/email-form'
import { mutationFeedback, networkFeedback } from '../../settings/lib/feedback'
import type { FieldError } from '../../settings/lib/settings-form'

export function EmailDeliveryPage() {
  const { settings } = useInstanceSettings()
  const blocked = useSettingsBlocker()
  if (blocked) return blocked
  if (!settings) {
    return (
      <div className="space-y-6" aria-busy="true">
        <SettingsGroupSkeleton rows={['switch']} />
        <SettingsGroupSkeleton rows={['control', 'control', 'control']} />
        <SettingsGroupSkeleton rows={['control', 'control']} />
      </div>
    )
  }
  return <EmailDeliveryForm key={settings.email.delivery.version} delivery={settings.email.delivery} />
}

/** A single-line text control at the end of a settings row. */
function TextControl({
  name,
  label,
  value,
  onChange,
  type = 'text',
  placeholder,
  autoComplete = 'off',
  invalid,
  errorId,
  disabled,
}: {
  name: string
  label: string
  value: string
  onChange: (value: string) => void
  type?: 'text' | 'email' | 'password' | 'url'
  placeholder?: string
  autoComplete?: string
  invalid?: boolean
  errorId?: string
  disabled?: boolean
}) {
  return (
    <Input
      name={name}
      type={type}
      value={value}
      onChange={(event) => onChange(event.currentTarget.value)}
      aria-label={label}
      aria-invalid={invalid || undefined}
      aria-describedby={invalid ? errorId : undefined}
      placeholder={placeholder}
      autoComplete={autoComplete}
      spellCheck={false}
      disabled={disabled}
      className="w-full sm:w-72"
    />
  )
}

function EmailDeliveryForm({ delivery }: { delivery: EmailDelivery }) {
  const t = useTranslator()
  const { query } = useInstanceSettings()
  const scope = useEmailScope()
  const mutations = useEmailMutations()
  const testDialog = useOverlayState()
  const errorPrefix = useId()
  const [draft, setDraft, resetDraft] = useSettingsDraft<EmailDeliveryDraft>(
    'email',
    delivery.version,
    () => emailDeliveryDraft(delivery),
  )
  const [errors, setErrors] = useState<Partial<Record<EmailDeliveryField, FieldError>>>({})
  const [serverErrors, setServerErrors] = useState<Record<string, string>>({})
  const [feedback, setFeedback] = useState<RbacFeedbackState | null>(null)
  const [pending, setPending] = useState(false)
  const editable = scope.deliveryWrite
  const disabled = pending || !editable
  const dirty = emailDeliveryDirty(delivery, draft)

  function change<K extends EmailDeliveryField>(field: K, value: EmailDeliveryDraft[K]) {
    setDraft((current) => {
      const next = { ...current, [field]: value }
      // Follow the conventional port while the operator has not chosen another.
      if (field === 'security' && current.port === String(SMTP_DEFAULT_PORTS[current.security])) {
        next.port = String(SMTP_DEFAULT_PORTS[value as EmailDeliveryDraft['security']])
      }
      return next
    })
    setErrors((current) => ({ ...current, [field]: undefined }))
    setServerErrors({})
    setFeedback(null)
  }

  async function save() {
    if (pending || !dirty) return
    const prepared = emailDeliveryInput(delivery, draft)
    if ('errors' in prepared) {
      setErrors(prepared.errors)
      return
    }
    setPending(true)
    setFeedback(null)
    try {
      const result = await mutations.updateDelivery(prepared.input)
      if (!result.data?.updateEmailDeliverySettings) {
        setServerErrors(serverFieldErrors(fieldErrorMap(result.errors)))
        setFeedback(mutationFeedback(result, 'missing_update_email_delivery_payload'))
        return
      }
      toast.success(t('settingsSavedToast'))
    } catch {
      setFeedback(networkFeedback('email_delivery_request_failed'))
    } finally {
      setPending(false)
    }
  }

  const message = (field: EmailDeliveryField) => {
    const local = errors[field]
    return local ? t(local.key, local.values) : serverErrors[field]
  }

  const textRow = (
    field: EmailDeliveryField,
    label: MessageKey,
    description: MessageKey | null,
    options: { type?: 'text' | 'email' | 'password' | 'url'; placeholder?: string } = {},
  ) => {
    const errorId = `${errorPrefix}-${field}`
    const error = message(field)
    return (
      <SettingsRow
        label={t(label)}
        description={description ? t(description) : undefined}
        action={
          <TextControl
            name={field}
            label={t(label)}
            value={String(draft[field])}
            onChange={(value) => change(field, value as never)}
            type={options.type}
            placeholder={options.placeholder}
            autoComplete={options.type === 'password' ? 'new-password' : 'off'}
            invalid={Boolean(error)}
            errorId={errorId}
            disabled={disabled}
          />
        }
      >
        {error ? <SettingsFieldError id={errorId} message={error} /> : null}
      </SettingsRow>
    )
  }

  const secretRow = (
    field: 'password' | 'clientSecret' | 'refreshToken',
    label: MessageKey,
    optional = false,
  ) => {
    const stored = storedSecret(delivery, draft, field)
    return textRow(
      field,
      label,
      stored ? 'settingsEmailSecretStored' : optional ? 'settingsEmailSecretOptional' : null,
      {
        type: 'password',
        placeholder: stored ? t('settingsEmailSecretKeep') : undefined,
      },
    )
  }

  const portError = message('port')
  const portErrorId = `${errorPrefix}-port`
  const toggleDescription: MessageKey = draft.enabled
    ? 'settingsEmailEnabledHint'
    : delivery.host.trim() || draft.host.trim()
      ? 'settingsEmailDisabledSavedHint'
      : 'settingsEmailDisabledHint'

  const testButton =
    scope.testEmail && (draft.enabled || delivery.configured) ? (
      <Button
        type="button"
        variant="outline"
        disabled={pending || !delivery.configured || dirty}
        title={
          dirty
            ? t('settingsEmailTestSaveFirst')
            : !delivery.configured
              ? t('settingsEmailTestUnavailable')
              : undefined
        }
        onClick={testDialog.open}
      >
        <Send className="size-4" aria-hidden="true" />
        {t('settingsEmailTestAction')}
      </Button>
    ) : null

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
        <SettingsGroup>
          <SettingsRow
            label={t('settingsEmailEnabled')}
            description={t(toggleDescription)}
            action={
              <SettingsSwitch
                label={t('settingsEmailEnabled')}
                isSelected={draft.enabled}
                onChange={(value) => change('enabled', value)}
                isDisabled={disabled}
              />
            }
          />
        </SettingsGroup>

        {draft.enabled ? (
          <>
            <SettingsGroup title={t('settingsEmailDeliverySection')}>
              {textRow('host', 'settingsEmailHost', 'settingsEmailHostHint', {
                placeholder: 'smtp.example.com',
              })}
              <SettingsRow
                label={t('settingsEmailSecurity')}
                description={t('settingsEmailSecurityHint')}
                action={
                  <SettingsSelect
                    label={t('settingsEmailSecurity')}
                    value={draft.security}
                    onChange={(value) => change('security', value as EmailDeliveryDraft['security'])}
                    options={[
                      { id: 'START_TLS', label: t('settingsEmailSecurityStartTls') },
                      { id: 'TLS', label: t('settingsEmailSecurityTls') },
                      { id: 'NONE', label: t('settingsEmailSecurityNone') },
                    ]}
                    isDisabled={disabled}
                  />
                }
              />
              <SettingsRow
                label={t('settingsEmailPort')}
                description={t('settingsEmailPortHint')}
                action={
                  <SettingsNumberInput
                    name="port"
                    label={t('settingsEmailPort')}
                    value={draft.port}
                    onChange={(value) => change('port', value)}
                    min={delivery.portRange.min}
                    max={delivery.portRange.max}
                    invalid={Boolean(portError)}
                    errorId={portErrorId}
                    isDisabled={disabled}
                  />
                }
              >
                {portError ? <SettingsFieldError id={portErrorId} message={portError} /> : null}
              </SettingsRow>
            </SettingsGroup>

            <SettingsGroup title={t('settingsEmailSenderSection')}>
              {textRow('senderAddress', 'settingsEmailSenderAddress', 'settingsEmailSenderAddressHint', {
                type: 'email',
                placeholder: 'no-reply@example.com',
              })}
              {textRow('senderName', 'settingsEmailSenderName', 'settingsEmailSenderNameHint')}
            </SettingsGroup>

            <SettingsGroup
              title={t('settingsEmailAuthenticationSection')}
              description={t('settingsEmailAuthenticationSectionHint')}
            >
              <SettingsRow
                label={t('settingsEmailAuthenticationMethod')}
                action={
                  <SettingsSelect
                    label={t('settingsEmailAuthenticationMethod')}
                    value={draft.method}
                    onChange={(value) => change('method', value as EmailDeliveryDraft['method'])}
                    options={[
                      { id: 'PASSWORD', label: t('settingsEmailMethodPassword') },
                      { id: 'XOAUTH2', label: t('settingsEmailMethodXoauth2') },
                      { id: 'NONE', label: t('settingsEmailMethodNone') },
                    ]}
                    isDisabled={disabled}
                  />
                }
              />
              {draft.method !== 'NONE'
                ? textRow('username', 'settingsEmailUsername', draft.method === 'XOAUTH2'
                    ? 'settingsEmailXoauth2UsernameHint'
                    : null)
                : null}
              {draft.method === 'PASSWORD' ? secretRow('password', 'settingsEmailPassword') : null}
              {draft.method === 'XOAUTH2' ? (
                <>
                  {textRow('tokenEndpoint', 'settingsEmailTokenEndpoint', 'settingsEmailTokenEndpointHint', {
                    type: 'url',
                    placeholder: 'https://oauth2.example.com/token',
                  })}
                  {textRow('clientId', 'settingsEmailClientId', null)}
                  {secretRow('clientSecret', 'settingsEmailClientSecret', true)}
                  <SettingsRow
                    label={t('settingsEmailGrant')}
                    description={t('settingsEmailGrantHint')}
                    action={
                      <SettingsSelect
                        label={t('settingsEmailGrant')}
                        value={draft.grant}
                        onChange={(value) => change('grant', value as EmailDeliveryDraft['grant'])}
                        options={[
                          { id: 'REFRESH_TOKEN', label: t('settingsEmailGrantRefreshToken') },
                          { id: 'CLIENT_CREDENTIALS', label: t('settingsEmailGrantClientCredentials') },
                        ]}
                        isDisabled={disabled}
                      />
                    }
                  />
                  {draft.grant === 'REFRESH_TOKEN'
                    ? secretRow('refreshToken', 'settingsEmailRefreshToken')
                    : null}
                  {textRow('scope', 'settingsEmailScope', 'settingsEmailScopeHint')}
                </>
              ) : null}
            </SettingsGroup>
          </>
        ) : null}

        {editable ? (
          <SettingsFormFooter
            dirty={dirty}
            pending={pending}
            leading={testButton}
            onDiscard={() => {
              resetDraft()
              setErrors({})
              setServerErrors({})
              setFeedback(null)
            }}
          />
        ) : testButton ? (
          <div className="flex flex-wrap items-center gap-3">{testButton}</div>
        ) : null}
      </form>
      {scope.testEmail ? <SendTestEmailDialog state={testDialog} /> : null}
    </div>
  )
}

/** Server field paths are relative to the input (`authentication.password`). */
function serverFieldErrors(fields: Record<string, string>): Record<string, string> {
  const result: Record<string, string> = {}
  for (const [path, value] of Object.entries(fields)) {
    const key = path.split('.').filter(Boolean).at(-1)
    if (key && !result[key]) result[key] = value
  }
  return result
}
