import type {
  EmailAuthenticationMethod,
  EmailTemplateKind,
  EmailTemplatePreviewScenario,
  SmtpSecurity,
  UpdateEmailDeliverySettingsInput,
  UpdateEmailPolicySettingsInput,
  UpdateEmailTemplateInput,
  Xoauth2Grant,
} from '#/generated/graphql'
import type { MessageKey } from '#/lib/i18n'
import {
  parseWholeNumber,
  type FieldError,
  type InstanceSettings,
  type SettingRange,
} from '../../settings/lib/settings-form'

export type EmailSettings = InstanceSettings['email']
export type EmailDelivery = EmailSettings['delivery']
export type EmailPolicy = EmailSettings['policy']
export type EmailTemplate = EmailSettings['templates'][number]
export type LocalizedEmailTemplate = EmailTemplate['content']

/**
 * What an operator edits. Secrets start empty: an empty secret keeps the
 * stored one while the method stays the same.
 */
export interface EmailDeliveryDraft {
  enabled: boolean
  host: string
  port: string
  security: SmtpSecurity
  senderAddress: string
  senderName: string
  method: EmailAuthenticationMethod
  username: string
  password: string
  tokenEndpoint: string
  clientId: string
  clientSecret: string
  grant: Xoauth2Grant
  refreshToken: string
  scope: string
}

export type EmailDeliveryField = keyof EmailDeliveryDraft

export function emailDeliveryDraft(delivery: EmailDelivery): EmailDeliveryDraft {
  const auth = delivery.authentication
  return {
    enabled: delivery.enabled,
    host: delivery.host,
    port: String(delivery.port),
    security: delivery.security,
    senderAddress: delivery.senderAddress,
    senderName: delivery.senderName ?? '',
    method: auth.method,
    username: auth.username ?? '',
    password: '',
    tokenEndpoint: auth.tokenEndpoint ?? '',
    clientId: auth.clientId ?? '',
    clientSecret: '',
    grant: auth.grant ?? 'REFRESH_TOKEN',
    refreshToken: '',
    scope: auth.scope ?? '',
  }
}

/** The conventional port of each connection security. */
export const SMTP_DEFAULT_PORTS: Record<SmtpSecurity, number> = {
  TLS: 465,
  START_TLS: 587,
  NONE: 25,
}

/** Whether a secret is already stored for the method being edited. */
export function storedSecret(
  delivery: EmailDelivery,
  draft: EmailDeliveryDraft,
  secret: 'password' | 'clientSecret' | 'refreshToken',
) {
  const auth = delivery.authentication
  if (auth.method !== draft.method) return false
  if (secret === 'password') return auth.passwordSet
  if (secret === 'clientSecret') return auth.clientSecretSet
  return auth.refreshTokenSet
}

function optional(value: string) {
  const trimmed = value.trim()
  return trimmed ? trimmed : null
}

/**
 * While delivery is off, its fields are collapsed and not applied; only turning
 * an active delivery off is an unsaved change.
 */
export function emailDeliveryDirty(delivery: EmailDelivery, draft: EmailDeliveryDraft): boolean {
  if (!draft.enabled) return delivery.enabled
  return JSON.stringify(draft) !== JSON.stringify(emailDeliveryDraft(delivery))
}

/** The mutation input for `draft`, or the fields that need attention. */
export function emailDeliveryInput(
  delivery: EmailDelivery,
  draft: EmailDeliveryDraft,
):
  | { input: Omit<UpdateEmailDeliverySettingsInput, 'clientMutationId'> }
  | { errors: Partial<Record<EmailDeliveryField, FieldError>> } {
  if (!draft.enabled) {
    const auth = delivery.authentication
    return {
      input: {
        enabled: false,
        host: delivery.host,
        port: delivery.port,
        security: delivery.security,
        senderAddress: delivery.senderAddress,
        senderName: delivery.senderName,
        authentication:
          auth.method === 'NONE'
            ? { method: 'NONE' }
            : auth.method === 'PASSWORD'
              ? {
                  method: 'PASSWORD',
                  username: auth.username ?? '',
                  password: null,
                }
              : {
                  method: 'XOAUTH2',
                  username: auth.username ?? '',
                  tokenEndpoint: auth.tokenEndpoint ?? '',
                  clientId: auth.clientId ?? '',
                  clientSecret: null,
                  grant: auth.grant ?? 'REFRESH_TOKEN',
                  refreshToken: null,
                  scope: auth.scope,
                },
        expectedVersion: delivery.version,
      },
    }
  }
  const errors: Partial<Record<EmailDeliveryField, FieldError>> = {}
  const required = (field: EmailDeliveryField, value: string) => {
    if (!value.trim()) errors[field] = { key: 'settingsEmailRequired' }
  }
  const port = parseWholeNumber(draft.port, delivery.portRange)
  if ('error' in port) errors.port = port.error
  required('host', draft.host)
  required('senderAddress', draft.senderAddress)
  if (draft.senderAddress.trim() && !/^[^\s@]+@[^\s@]+$/u.test(draft.senderAddress.trim())) {
    errors.senderAddress = { key: 'settingsEmailInvalidAddress' }
  }
  if (draft.method !== 'NONE') required('username', draft.username)
  if (draft.method === 'PASSWORD' && !storedSecret(delivery, draft, 'password')) {
    required('password', draft.password)
  }
  if (draft.method === 'XOAUTH2') {
    required('tokenEndpoint', draft.tokenEndpoint)
    required('clientId', draft.clientId)
    if (draft.grant === 'REFRESH_TOKEN' && !storedSecret(delivery, draft, 'refreshToken')) {
      required('refreshToken', draft.refreshToken)
    }
  }
  if (Object.keys(errors).length) return { errors }
  const secret = (value: string) => (value ? value : null)
  return {
    input: {
      enabled: true,
      host: draft.host.trim(),
      port: 'value' in port ? port.value : 0,
      security: draft.security,
      senderAddress: draft.senderAddress.trim(),
      senderName: optional(draft.senderName),
      authentication:
        draft.method === 'NONE'
          ? { method: 'NONE' }
          : draft.method === 'PASSWORD'
            ? {
                method: 'PASSWORD',
                username: draft.username.trim(),
                password: secret(draft.password),
              }
            : {
                method: 'XOAUTH2',
                username: draft.username.trim(),
                tokenEndpoint: draft.tokenEndpoint.trim(),
                clientId: draft.clientId.trim(),
                clientSecret: secret(draft.clientSecret),
                grant: draft.grant,
                refreshToken: draft.grant === 'REFRESH_TOKEN' ? secret(draft.refreshToken) : null,
                scope: optional(draft.scope),
              },
      expectedVersion: delivery.version,
    },
  }
}

/** URL segment of each template kind. */
const templateSlugs: Record<EmailTemplateKind, string> = {
  SIGN_IN_CODE: 'sign-in-code',
  EMAIL_VERIFICATION: 'email-verification',
  PASSWORD_RESET: 'password-reset',
  USER_INVITATION: 'user-invitation',
  REGISTRATION: 'registration',
}

export function emailTemplateSlug(kind: EmailTemplateKind) {
  return templateSlugs[kind]
}

export function emailTemplateKind(slug: string): EmailTemplateKind | undefined {
  return (Object.keys(templateSlugs) as EmailTemplateKind[]).find(
    (kind) => templateSlugs[kind] === slug,
  )
}

export const emailTemplateLabels: Record<
  EmailTemplateKind,
  { title: MessageKey; description: MessageKey }
> = {
  SIGN_IN_CODE: {
    title: 'settingsEmailTemplateSignInCode',
    description: 'settingsEmailTemplateSignInCodeHint',
  },
  EMAIL_VERIFICATION: {
    title: 'settingsEmailTemplateEmailVerification',
    description: 'settingsEmailTemplateEmailVerificationHint',
  },
  PASSWORD_RESET: {
    title: 'settingsEmailTemplatePasswordReset',
    description: 'settingsEmailTemplatePasswordResetHint',
  },
  USER_INVITATION: {
    title: 'settingsEmailTemplateUserInvitation',
    description: 'settingsEmailTemplateUserInvitationHint',
  },
  REGISTRATION: {
    title: 'settingsEmailTemplateRegistration',
    description: 'settingsEmailTemplateRegistrationHint',
  },
}

export const emailTemplatePreviewScenarioLabels: Record<EmailTemplatePreviewScenario, MessageKey> = {
  SIGN_IN_CODE_WITH_APPLICATION: 'settingsEmailScenarioSignInCodeWithApplication',
  SIGN_IN_CODE_WITHOUT_APPLICATION: 'settingsEmailScenarioSignInCodeWithoutApplication',
  EMAIL_VERIFICATION_CHANGE_ADDRESS: 'settingsEmailScenarioEmailVerificationChangeAddress',
  EMAIL_VERIFICATION_CURRENT_ADDRESS: 'settingsEmailScenarioEmailVerificationCurrentAddress',
  REGISTRATION_NEW_ACCOUNT: 'settingsEmailScenarioRegistrationNewAccount',
  REGISTRATION_EXISTING_ACCOUNT: 'settingsEmailScenarioRegistrationExistingAccount',
}

export interface EmailTemplateContentDraft {
  subject: string
  html: string
}

export interface EmailTemplateTranslationDraft {
  locale: string
  content: EmailTemplateContentDraft
}

/**
 * A template being edited. Like other localized text it has default content,
 * used when no translation fits the reader, and translations in any language.
 */
export interface EmailTemplateDraft {
  customized: boolean
  default: EmailTemplateContentDraft
  translations: EmailTemplateTranslationDraft[]
}

/** The language being edited: `null` is the default content. */
export type EmailTemplateLanguage = string | null

function copy(template: LocalizedEmailTemplate): Omit<EmailTemplateDraft, 'customized'> {
  return {
    default: { ...template.default },
    translations: template.translations.map((translation) => ({
      locale: translation.locale,
      content: { ...translation.content },
    })),
  }
}

export function emailTemplateDraft(template: EmailTemplate): EmailTemplateDraft {
  return { customized: template.customized, ...copy(template.content) }
}

/** Start customizing from the built-in template, so nothing is lost. */
export function customizeEmailTemplate(template: EmailTemplate): EmailTemplateDraft {
  return { customized: true, ...copy(template.builtIn) }
}

/** What is sent while the draft is in effect. */
export function effectiveEmailTemplate(
  template: EmailTemplate,
  draft: EmailTemplateDraft,
): Omit<EmailTemplateDraft, 'customized'> {
  return draft.customized ? draft : copy(template.builtIn)
}

export function templateContent(
  template: Omit<EmailTemplateDraft, 'customized'>,
  language: EmailTemplateLanguage,
): EmailTemplateContentDraft | undefined {
  if (language === null) return template.default
  return template.translations.find((translation) => translation.locale === language)?.content
}

/** Replace the content of one language. */
export function updateTemplateContent(
  draft: EmailTemplateDraft,
  language: EmailTemplateLanguage,
  patch: Partial<EmailTemplateContentDraft>,
): EmailTemplateDraft {
  if (language === null) return { ...draft, default: { ...draft.default, ...patch } }
  return {
    ...draft,
    translations: draft.translations.map((translation) =>
      translation.locale === language
        ? { ...translation, content: { ...translation.content, ...patch } }
        : translation,
    ),
  }
}

export function addTemplateTranslation(
  draft: EmailTemplateDraft,
  locale: string,
  content: EmailTemplateContentDraft,
): EmailTemplateDraft {
  if (draft.translations.some((translation) => translation.locale === locale)) return draft
  return {
    ...draft,
    translations: [...draft.translations, { locale, content: { ...content } }].sort((a, b) =>
      a.locale.localeCompare(b.locale),
    ),
  }
}

export function removeTemplateTranslation(
  draft: EmailTemplateDraft,
  locale: string,
): EmailTemplateDraft {
  return {
    ...draft,
    translations: draft.translations.filter((translation) => translation.locale !== locale),
  }
}

export function emailTemplateInput(
  template: EmailTemplate,
  draft: EmailTemplateDraft,
): Omit<UpdateEmailTemplateInput, 'clientMutationId'> {
  return {
    kind: template.kind,
    content: draft.customized
      ? {
          default: { ...draft.default },
          translations: draft.translations.map((translation) => ({
            locale: translation.locale,
            content: { ...translation.content },
          })),
        }
      : null,
    expectedVersion: template.version,
  }
}

/** The key of a language in {@link templateFieldErrors}. */
export function languageKey(language: EmailTemplateLanguage) {
  return language ?? ''
}

/**
 * Server field errors of a template save, by language and part:
 * `content.default.html` and `content.translations.<index>.content.html`
 * (paths may carry an `input.` prefix).
 */
export function templateFieldErrors(
  draft: EmailTemplateDraft,
  fields: Record<string, string>,
): Record<string, Partial<Record<keyof EmailTemplateContentDraft | 'locale', string>>> {
  const result: Record<
    string,
    Partial<Record<keyof EmailTemplateContentDraft | 'locale', string>>
  > = {}
  for (const [path, message] of Object.entries(fields)) {
    const defaultMatch = /(?:^|\.)default\.(subject|html)$/u.exec(path)
    const translationMatch =
      /(?:^|\.)translations\.(\d+)\.(?:content\.(subject|html)|(locale))$/u.exec(path)
    let language: EmailTemplateLanguage | undefined
    let part: keyof EmailTemplateContentDraft | 'locale' | undefined
    if (defaultMatch) {
      language = null
      part = defaultMatch[1] as keyof EmailTemplateContentDraft
    } else if (translationMatch) {
      language = draft.translations[Number(translationMatch[1])]?.locale
      part = (translationMatch[2] ?? translationMatch[3]) as keyof EmailTemplateContentDraft | 'locale'
    }
    if (language === undefined || !part) continue
    const key = languageKey(language)
    result[key] = { ...result[key], [part]: message }
  }
  return result
}

export interface EmailPolicyDraft {
  signInCodeLifetimeMinutes: string
  passwordResetLifetimeMinutes: string
  registrationLifetimeMinutes: string
  emailVerificationLifetimeHours: string
  userInvitationLifetimeDays: string
  resendIntervalSeconds: string
  loginMaxSends: string
  verificationMaxSends: string
  verificationSendWindowHours: string
}

export type EmailPolicyNumberField = keyof EmailPolicyDraft

export function emailPolicyDraft(policy: EmailPolicy): EmailPolicyDraft {
  return {
    signInCodeLifetimeMinutes: String(policy.signInCodeLifetimeMinutes),
    passwordResetLifetimeMinutes: String(policy.passwordResetLifetimeMinutes),
    registrationLifetimeMinutes: String(policy.registrationLifetimeMinutes),
    emailVerificationLifetimeHours: String(policy.emailVerificationLifetimeHours),
    userInvitationLifetimeDays: String(policy.userInvitationLifetimeDays),
    resendIntervalSeconds: String(policy.resendIntervalSeconds),
    loginMaxSends: String(policy.loginMaxSends),
    verificationMaxSends: String(policy.verificationMaxSends),
    verificationSendWindowHours: String(policy.verificationSendWindowHours),
  }
}

const emailPolicyRanges: Record<EmailPolicyNumberField, (policy: EmailPolicy) => SettingRange> = {
  signInCodeLifetimeMinutes: (policy) => policy.signInCodeLifetimeMinutesRange,
  passwordResetLifetimeMinutes: (policy) => policy.passwordResetLifetimeMinutesRange,
  registrationLifetimeMinutes: (policy) => policy.registrationLifetimeMinutesRange,
  emailVerificationLifetimeHours: (policy) => policy.emailVerificationLifetimeHoursRange,
  userInvitationLifetimeDays: (policy) => policy.userInvitationLifetimeDaysRange,
  resendIntervalSeconds: (policy) => policy.resendIntervalSecondsRange,
  loginMaxSends: (policy) => policy.loginMaxSendsRange,
  verificationMaxSends: (policy) => policy.verificationMaxSendsRange,
  verificationSendWindowHours: (policy) => policy.verificationSendWindowHoursRange,
}

export function emailPolicyRange(policy: EmailPolicy, field: EmailPolicyNumberField): SettingRange {
  return emailPolicyRanges[field](policy)
}

export function emailPolicyInput(
  policy: EmailPolicy,
  draft: EmailPolicyDraft,
):
  | { input: Omit<UpdateEmailPolicySettingsInput, 'clientMutationId'> }
  | { errors: Partial<Record<EmailPolicyNumberField, FieldError>> } {
  const errors: Partial<Record<EmailPolicyNumberField, FieldError>> = {}
  const values: Partial<Record<EmailPolicyNumberField, number>> = {}
  for (const field of Object.keys(emailPolicyRanges) as EmailPolicyNumberField[]) {
    const parsed = parseWholeNumber(draft[field], emailPolicyRange(policy, field))
    if ('error' in parsed) errors[field] = parsed.error
    else values[field] = parsed.value
  }
  if (Object.keys(errors).length) return { errors }
  return {
    input: {
      signInCodeLifetimeMinutes: values.signInCodeLifetimeMinutes!,
      passwordResetLifetimeMinutes: values.passwordResetLifetimeMinutes!,
      registrationLifetimeMinutes: values.registrationLifetimeMinutes!,
      emailVerificationLifetimeHours: values.emailVerificationLifetimeHours!,
      userInvitationLifetimeDays: values.userInvitationLifetimeDays!,
      resendIntervalSeconds: values.resendIntervalSeconds!,
      loginMaxSends: values.loginMaxSends!,
      verificationMaxSends: values.verificationMaxSends!,
      verificationSendWindowHours: values.verificationSendWindowHours!,
      expectedVersion: policy.version,
    },
  }
}
