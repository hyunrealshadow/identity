import { Button } from '@identity/ui/components/button'
import { Field, FieldDescription, FieldError, FieldLabel } from '@identity/ui/components/field'
import { Input } from '@identity/ui/components/input'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@identity/ui/components/select'
import { Skeleton } from '@identity/ui/components/skeleton'
import { Link } from '@tanstack/react-router'
import { ArrowLeft, Plus, Undo2, X } from 'lucide-react'
import { useId, useRef, useState } from 'react'

import { useBreadcrumbLabel } from '#/components/app-breadcrumbs'
import { SettingsGroup, SettingsGroupSkeleton, SettingsRow, SettingsSwitch } from '#/components/settings-section'
import { TranslationLanguagePicker } from '#/components/translation-language-picker'
import { fieldErrorMap } from '#/lib/graphql/transport'
import { useLocale, useTranslator } from '#/lib/i18n'
import { MAX_TRANSLATIONS } from '#/lib/localized-values'
import { toast } from '#/lib/toast'
import { translationLocaleLabel } from '#/lib/translation-locales'
import { RbacMutationFeedback } from '#/modules/user-management/components/rbac-feedback'
import type { RbacFeedbackState } from '#/modules/user-management/lib/rbac-errors'
import { SettingsFormFooter } from '../../settings/components/settings-form-footer'
import {
  useInstanceSettings,
  useSettingsBlocker,
  useSettingsDraft,
} from '../../settings/components/instance-settings-context'
import { mutationFeedback, networkFeedback } from '../../settings/lib/feedback'
import { EmailPreview } from '../components/email-preview'
import { HtmlCodeEditor } from '../components/html-code-editor'
import { useEmailMutations } from '../hooks/email-mutations'
import {
  addTemplateTranslation,
  customizeEmailTemplate,
  effectiveEmailTemplate,
  emailTemplateDraft,
  emailTemplateInput,
  emailTemplateKind,
  emailTemplateLabels,
  languageKey,
  removeTemplateTranslation,
  templateContent,
  templateFieldErrors,
  updateTemplateContent,
  type EmailTemplate,
  type EmailTemplateContentDraft,
  type EmailTemplateDraft,
  type EmailTemplateLanguage,
  type EmailTemplateTranslationDraft,
} from '../lib/email-form'
import { useEmailScope } from '../lib/email-scope'

/** Select value of the default content; language tags never start with `@`. */
const DEFAULT_LANGUAGE = '@default'

export function EmailTemplatePage({ slug }: { slug: string }) {
  const t = useTranslator()
  const { settings } = useInstanceSettings()
  const blocked = useSettingsBlocker()
  const kind = emailTemplateKind(slug)
  useBreadcrumbLabel(`/email/templates/${slug}`, kind ? t(emailTemplateLabels[kind].title) : undefined)
  if (blocked) return blocked
  const back = (
    <Link to="/email/templates" className="mb-4 inline-flex items-center gap-1.5 text-sm text-link">
      <ArrowLeft className="size-4" aria-hidden="true" />
      {t('emailAllTemplates')}
    </Link>
  )
  if (!settings) {
    return (
      <div aria-busy="true">
        {back}
        <div className="grid gap-6 xl:grid-cols-2">
          <SettingsGroupSkeleton rows={['switch', 'control', 'textarea']} />
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

type PartErrors = Partial<Record<keyof EmailTemplateContentDraft | 'locale', string>>

function EmailTemplateForm({ template }: { template: EmailTemplate }) {
  const t = useTranslator()
  const { locale: uiLocale } = useLocale()
  const { query } = useInstanceSettings()
  const scope = useEmailScope()
  const mutations = useEmailMutations()
  const fieldId = useId()
  const addPanelId = useId()
  const addButtonRef = useRef<HTMLButtonElement | null>(null)
  const initial = emailTemplateDraft(template)
  const [draft, setDraft, resetDraft] = useSettingsDraft<EmailTemplateDraft>(
    `email_template.${template.kind}`,
    template.version,
    () => emailTemplateDraft(template),
  )
  const [language, setLanguage] = useState<EmailTemplateLanguage>(null)
  const [addOpen, setAddOpen] = useState(false)
  const [removed, setRemoved] = useState<EmailTemplateTranslationDraft | null>(null)
  const [errors, setErrors] = useState<Record<string, PartErrors>>({})
  const [feedback, setFeedback] = useState<RbacFeedbackState | null>(null)
  const [pending, setPending] = useState(false)
  const editable = scope.templateWrite
  const disabled = pending || !editable
  const readOnly = !draft.customized
  const dirty = JSON.stringify(draft) !== JSON.stringify(initial)
  const labels = emailTemplateLabels[template.kind]
  const shown = effectiveEmailTemplate(template, draft)
  const content = templateContent(shown, language) ?? shown.default
  const activeLanguage = templateContent(shown, language) ? language : null
  const partErrors = errors[languageKey(activeLanguage)] ?? {}
  const atMax = draft.translations.length >= MAX_TRANSLATIONS
  const usedLocalesKey = draft.translations.map((translation) => translation.locale).join('\0')

  function changeDraft(next: EmailTemplateDraft) {
    setDraft(next)
    setFeedback(null)
  }

  function clearErrors(key: string) {
    setErrors((current) => ({ ...current, [key]: {} }))
  }

  function setCustomized(customized: boolean) {
    setAddOpen(false)
    setRemoved(null)
    setErrors({})
    if (customized) {
      // Start from what is sent today so nothing is lost.
      changeDraft(draft.customized ? draft : customizeEmailTemplate(template))
    } else {
      changeDraft({ ...draft, customized: false })
    }
  }

  function addTranslation(tag: string) {
    // A new translation starts from the default content, ready to translate.
    changeDraft(addTemplateTranslation(draft, tag, draft.default))
    setLanguage(tag)
    setAddOpen(false)
    setRemoved((previous) => (previous?.locale === tag ? null : previous))
  }

  function removeTranslation() {
    if (activeLanguage === null) return
    const translation = draft.translations.find((entry) => entry.locale === activeLanguage)
    if (!translation) return
    setRemoved(translation)
    changeDraft(removeTemplateTranslation(draft, activeLanguage))
    clearErrors(activeLanguage)
    setLanguage(null)
  }

  function undoRemoval() {
    if (!removed || atMax) return
    changeDraft(addTemplateTranslation(draft, removed.locale, removed.content))
    setLanguage(removed.locale)
    setRemoved(null)
  }

  async function save() {
    if (pending || !dirty) return
    setPending(true)
    setFeedback(null)
    try {
      const result = await mutations.updateTemplate(emailTemplateInput(template, draft))
      if (!result.data?.updateEmailTemplate) {
        const byLanguage = templateFieldErrors(draft, fieldErrorMap(result.errors))
        setErrors(byLanguage)
        const first = Object.keys(byLanguage)[0]
        if (first !== undefined) setLanguage(first === '' ? null : first)
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

  const languageLabel = (value: EmailTemplateLanguage) =>
    value === null ? t('localizedDefault') : translationLocaleLabel(value, uiLocale)

  const part = (name: keyof EmailTemplateContentDraft, label: string) => {
    const id = `${fieldId}-${name}`
    const error = partErrors[name]
    const change = (value: string) => {
      changeDraft(updateTemplateContent(draft, activeLanguage, { [name]: value }))
      clearErrors(languageKey(activeLanguage))
    }
    const describedBy = error ? `${id}-error` : undefined
    return (
      <Field data-invalid={error ? true : undefined}>
        <FieldLabel id={`${id}-label`} htmlFor={id}>
          {label}
        </FieldLabel>
        {name === 'html' ? (
          <HtmlCodeEditor
            id={id}
            labelId={`${id}-label`}
            value={content[name]}
            onChange={change}
            readOnly={readOnly}
            disabled={disabled && !readOnly}
            invalid={Boolean(error)}
            describedBy={describedBy}
          />
        ) : (
          <Input
            id={id}
            name={`${languageKey(activeLanguage) || 'default'}.${name}`}
            value={content[name]}
            onChange={(event) => change(event.currentTarget.value)}
            readOnly={readOnly}
            disabled={disabled && !readOnly}
            spellCheck={false}
            aria-invalid={error ? true : undefined}
            aria-describedby={describedBy}
          />
        )}
        {error ? <FieldError id={describedBy}>{error}</FieldError> : null}
      </Field>
    )
  }

  const languages: EmailTemplateLanguage[] = [
    null,
    ...shown.translations.map((translation) => translation.locale),
  ]

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
                  onChange={setCustomized}
                  isDisabled={disabled}
                />
              }
            />
            <SettingsRow
              label={t('localizedLanguage')}
              description={t(
                activeLanguage === null ? 'emailTemplateDefaultHint' : 'emailTemplateTranslationHint',
              )}
              action={
                <Select
                  value={activeLanguage ?? DEFAULT_LANGUAGE}
                  onValueChange={(next) => {
                    if (next !== null) setLanguage(next === DEFAULT_LANGUAGE ? null : String(next))
                  }}
                  items={languages.map((value) => ({
                    value: value ?? DEFAULT_LANGUAGE,
                    label: languageLabel(value),
                  }))}
                >
                  <SelectTrigger aria-label={t('localizedLanguage')} className="min-h-8 w-56 py-1">
                    <SelectValue className="truncate" />
                  </SelectTrigger>
                  <SelectContent>
                    {languages.map((value) => {
                      const key = languageKey(value)
                      const invalid = Object.keys(errors[key] ?? {}).length > 0
                      return (
                        <SelectItem key={key || DEFAULT_LANGUAGE} value={value ?? DEFAULT_LANGUAGE}>
                          <span className="flex items-center gap-2">
                            {languageLabel(value)}
                            {invalid ? (
                              <span className="size-1.5 rounded-full bg-destructive" aria-hidden="true" />
                            ) : null}
                          </span>
                        </SelectItem>
                      )
                    })}
                  </SelectContent>
                </Select>
              }
            >
              {!readOnly ? (
                <div className="space-y-2">
                  <div className="flex min-w-0 flex-wrap items-center gap-1.5">
                    <span className="text-xs tabular-nums text-muted-foreground">
                      {t('emailTemplateTranslationCount', { count: draft.translations.length })}
                    </span>
                    <Button
                      ref={addButtonRef}
                      type="button"
                      size="sm"
                      variant="ghost"
                      disabled={disabled || atMax}
                      aria-expanded={addOpen}
                      aria-controls={addPanelId}
                      onClick={() => setAddOpen((open) => !open)}
                    >
                      <Plus aria-hidden="true" />
                      {t('localizedAddTranslation')}
                    </Button>
                    <Button
                      type="button"
                      size="sm"
                      variant="ghost"
                      className="text-destructive"
                      disabled={disabled || activeLanguage === null}
                      aria-label={
                        activeLanguage === null
                          ? t('localizedRemoveTranslation')
                          : t('localizedRemoveTranslationFor', { locale: activeLanguage })
                      }
                      onClick={removeTranslation}
                    >
                      <X aria-hidden="true" />
                      {t('localizedRemoveTranslation')}
                    </Button>
                    {removed ? (
                      <span className="flex items-center gap-1 text-xs text-muted-foreground">
                        <span role="status">
                          {t('localizedTranslationRemoved', { locale: removed.locale })}
                        </span>
                        <Button
                          type="button"
                          size="sm"
                          variant="ghost"
                          disabled={disabled || atMax}
                          onClick={undoRemoval}
                        >
                          <Undo2 aria-hidden="true" />
                          {t('localizedUndoRemove')}
                        </Button>
                      </span>
                    ) : null}
                  </div>
                  {atMax ? (
                    <p className="text-xs text-muted-foreground">
                      {t('localizedMaxTranslations', { max: MAX_TRANSLATIONS })}
                    </p>
                  ) : null}
                  {addOpen && !disabled && !atMax ? (
                    <div
                      id={addPanelId}
                      className="rounded-lg border border-border bg-muted p-3"
                      onKeyDown={(event) => {
                        if (event.key === 'Enter') event.preventDefault()
                        if (event.key === 'Escape' && !event.defaultPrevented) {
                          event.preventDefault()
                          setAddOpen(false)
                          addButtonRef.current?.focus()
                        }
                      }}
                    >
                      <TranslationLanguagePicker
                        usedLocalesKey={usedLocalesKey}
                        onSelect={addTranslation}
                        onCancel={() => {
                          setAddOpen(false)
                          addButtonRef.current?.focus()
                        }}
                      />
                    </div>
                  ) : null}
                  {partErrors.locale ? (
                    <p role="alert" className="text-xs text-destructive">
                      {partErrors.locale}
                    </p>
                  ) : null}
                </div>
              ) : null}
            </SettingsRow>
            <SettingsRow>
              <div className="space-y-4">
                {part('subject', t('settingsEmailTemplateSubject'))}
                {part('html', t('settingsEmailTemplateHtml'))}
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
            locale={activeLanguage}
            content={content}
            enabled={scope.preview}
          />
        </div>

        {editable ? (
          <SettingsFormFooter
            dirty={dirty}
            pending={pending}
            onDiscard={() => {
              resetDraft()
              setErrors({})
              setFeedback(null)
              setRemoved(null)
              setAddOpen(false)
              setLanguage(null)
            }}
          />
        ) : null}
      </form>
    </div>
  )
}
