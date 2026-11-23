import { Badge } from '@identity/ui/components/badge'
import { Field, FieldDescription, FieldError, FieldLabel } from '@identity/ui/components/field'
import { Input } from '@identity/ui/components/input'
import { Skeleton } from '@identity/ui/components/skeleton'
import { Textarea } from '@identity/ui/components/textarea'
import { Link } from '@tanstack/react-router'
import { ArrowLeft } from 'lucide-react'
import { useId, useState } from 'react'

import { SettingsGroup, SettingsGroupSkeleton, SettingsRow, SettingsSwitch } from '#/components/settings-section'
import { fieldErrorMap } from '#/lib/graphql/transport'
import { useLocale, useTranslator } from '#/lib/i18n'
import { toast } from '#/lib/toast'
import { translationLocaleLabel } from '#/lib/translation-locales'
import { RbacMutationFeedback } from '#/modules/user-management/components/rbac-feedback'
import type { RbacFeedbackState } from '#/modules/user-management/lib/rbac-errors'
import { SettingsFormFooter } from '../components/settings-form-footer'
import { useInstanceSettings, useSettingsBlocker } from '../components/settings-shell'
import { EmailPreview } from '../components/email-preview'
import { useSettingMutations } from '../hooks/setting-mutations'
import {
  defaultContent,
  effectiveContent,
  emailTemplateDraft,
  emailTemplateInput,
  emailTemplateKind,
  emailTemplateLabels,
  templateFieldErrors,
  type EmailTemplate,
  type EmailTemplateContentDraft,
  type EmailTemplateLocaleDraft,
} from '../lib/email-form'
import { mutationFeedback, networkFeedback } from '../lib/feedback'

export function EmailTemplatePage({ slug }: { slug: string }) {
  const t = useTranslator()
  const { settings } = useInstanceSettings()
  const blocked = useSettingsBlocker()
  const kind = emailTemplateKind(slug)
  if (blocked) return blocked
  const back = (
    <Link to="/settings/email" className="mb-4 inline-flex items-center gap-1.5 text-sm text-link">
      <ArrowLeft className="size-4" aria-hidden="true" />
      {t('settingsEmailBack')}
    </Link>
  )
  if (!settings) {
    return (
      <div aria-busy="true">
        {back}
        <div className="grid gap-6 xl:grid-cols-2">
          <SettingsGroupSkeleton rows={['switch', 'textarea', 'textarea']} />
          <div className="space-y-2" aria-hidden="true">
            <Skeleton className="h-4 w-24 rounded-lg" />
            <Skeleton className="h-[28rem] w-full rounded-xl" />
          </div>
        </div>
      </div>
    )
  }
  const template = settings.email.templates.find((entry) => entry.kind === kind)
  if (!template) {
    return (
      <div>
        {back}
        <p className="text-sm text-muted-foreground">{t('settingsEmailTemplateMissing')}</p>
      </div>
    )
  }
  return (
    <div>
      {back}
      <EmailTemplateForm key={template.version} template={template} />
    </div>
  )
}

function EmailTemplateForm({ template }: { template: EmailTemplate }) {
  const t = useTranslator()
  const { locale: uiLocale } = useLocale()
  const { scope, query } = useInstanceSettings()
  const mutations = useSettingMutations()
  const fieldId = useId()
  const initial = emailTemplateDraft(template)
  const [drafts, setDrafts] = useState<EmailTemplateLocaleDraft[]>(initial)
  const [active, setActive] = useState(
    () => initial.find((draft) => draft.locale === uiLocale)?.locale ?? initial[0]?.locale ?? '',
  )
  const [errors, setErrors] = useState<
    Record<string, Partial<Record<keyof EmailTemplateContentDraft, string>>>
  >({})
  const [feedback, setFeedback] = useState<RbacFeedbackState | null>(null)
  const [pending, setPending] = useState(false)
  const editable = scope.emailTemplateWrite
  const disabled = pending || !editable
  const dirty = JSON.stringify(drafts) !== JSON.stringify(initial)
  const labels = emailTemplateLabels[template.kind]
  const draft = drafts.find((entry) => entry.locale === active) ?? drafts[0]
  if (!draft) return null
  const content = effectiveContent(template, draft)
  const localeErrors = errors[draft.locale] ?? {}

  function update(patch: Partial<EmailTemplateLocaleDraft>) {
    setDrafts((current) =>
      current.map((entry) => (entry.locale === active ? { ...entry, ...patch } : entry)),
    )
    setErrors((current) => ({ ...current, [active]: {} }))
    setFeedback(null)
  }

  async function save() {
    if (pending || !dirty) return
    setPending(true)
    setFeedback(null)
    try {
      const result = await mutations.updateEmailTemplate(emailTemplateInput(template, drafts))
      if (!result.data?.updateEmailTemplate) {
        const byLocale = templateFieldErrors(drafts, fieldErrorMap(result.errors))
        setErrors(byLocale)
        const first = Object.keys(byLocale)[0]
        if (first) setActive(first)
        setFeedback(mutationFeedback(result, 'missing_update_email_template_payload'))
        return
      }
      toast.success(t('settingsSavedToast'))
    } catch {
      setFeedback(networkFeedback('email_template_request_failed'))
    } finally {
      setPending(false)
    }
  }

  const part = (
    name: keyof EmailTemplateContentDraft,
    label: string,
    multiline: boolean,
  ) => {
    const id = `${fieldId}-${name}`
    const error = localeErrors[name]
    const props = {
      id,
      name,
      value: content[name],
      onChange: (event: { currentTarget: { value: string } }) =>
        update({ [name]: event.currentTarget.value }),
      readOnly: !draft.customized,
      disabled: disabled && draft.customized,
      spellCheck: false,
      'aria-invalid': error ? true : undefined,
      'aria-describedby': error ? `${id}-error` : undefined,
    }
    return (
      <Field data-invalid={error ? true : undefined}>
        <FieldLabel htmlFor={id}>{label}</FieldLabel>
        {multiline ? (
          <Textarea {...props} rows={name === 'html' ? 16 : 9} className="font-mono text-xs leading-5" />
        ) : (
          <Input {...props} />
        )}
        {error ? <FieldError id={`${id}-error`}>{error}</FieldError> : null}
      </Field>
    )
  }

  return (
    <div className="space-y-6">
      <div>
        <h2 className="text-base font-semibold">{t(labels.title)}</h2>
        <p className="mt-0.5 text-sm text-muted-foreground">{t(labels.description)}</p>
      </div>
      {feedback ? (
        <RbacMutationFeedback
          feedback={feedback}
          onReload={() => void query.refresh()}
          reloadPending={query.refreshing}
          conflictTitleKey="settingsConflictTitle"
          conflictDescriptionKey="settingsConflictDescription"
        />
      ) : null}

      <div role="tablist" aria-label={t('settingsEmailTemplateLanguages')} className="flex gap-1 border-b border-border">
        {drafts.map((entry) => {
          const selected = entry.locale === active
          return (
            <button
              key={entry.locale}
              type="button"
              role="tab"
              aria-selected={selected}
              onClick={() => setActive(entry.locale)}
              className={
                'flex items-center gap-2 border-b-2 px-3 py-2 text-sm ' +
                (selected ? 'border-primary font-semibold' : 'border-transparent text-muted-foreground')
              }
            >
              {translationLocaleLabel(entry.locale, uiLocale)}
              {entry.customized ? (
                <Badge variant="secondary">{t('settingsEmailTemplateCustomized')}</Badge>
              ) : null}
              {errors[entry.locale] && Object.keys(errors[entry.locale] ?? {}).length ? (
                <span className="size-1.5 rounded-full bg-destructive" aria-hidden="true" />
              ) : null}
            </button>
          )
        })}
      </div>

      <form
        noValidate
        aria-busy={pending}
        className="space-y-6"
        onSubmit={(event) => {
          event.preventDefault()
          void save()
        }}
      >
        <div className="grid items-start gap-6 xl:grid-cols-2">
          <SettingsGroup>
            <SettingsRow
              label={t('settingsEmailTemplateCustomize')}
              description={t(
                draft.customized
                  ? 'settingsEmailTemplateCustomizeOnHint'
                  : 'settingsEmailTemplateCustomizeOffHint',
              )}
              action={
                <SettingsSwitch
                  label={t('settingsEmailTemplateCustomize')}
                  isSelected={draft.customized}
                  onChange={(customized) =>
                    update(
                      customized
                        ? { customized, ...defaultContent(template, draft.locale) }
                        : { customized },
                    )
                  }
                  isDisabled={disabled}
                />
              }
            />
            <SettingsRow>
              <div className="space-y-4">
                {part('subject', t('settingsEmailTemplateSubject'), false)}
                {part('html', t('settingsEmailTemplateHtml'), true)}
                {part('text', t('settingsEmailTemplateText'), true)}
              </div>
            </SettingsRow>
            <SettingsRow
              label={t('settingsEmailTemplateVariables')}
              description={t('settingsEmailTemplateVariablesHint')}
            >
              <ul className="flex flex-wrap gap-1.5">
                {template.variables.map((variable) => (
                  <li key={variable}>
                    <code className="rounded-md bg-muted px-1.5 py-0.5 font-mono text-xs">
                      {`{{ ${variable} }}`}
                    </code>
                  </li>
                ))}
              </ul>
              <FieldDescription className="mt-3">{t('settingsEmailTemplateSyntaxHint')}</FieldDescription>
            </SettingsRow>
          </SettingsGroup>

          <EmailPreview
            kind={template.kind}
            locale={draft.locale}
            content={content}
            enabled={scope.emailPreview}
          />
        </div>

        {editable ? (
          <SettingsFormFooter
            dirty={dirty}
            pending={pending}
            onDiscard={() => {
              setDrafts(initial)
              setErrors({})
              setFeedback(null)
            }}
          />
        ) : null}
      </form>
    </div>
  )
}
