import type {
  EmailAuthenticationMethod,
  EmailTemplateKind,
  SmtpSecurity,
  UpdateEmailDeliverySettingsInput,
  UpdateEmailTemplateInput,
  Xoauth2Grant,
} from '#/generated/graphql'
import type { MessageKey } from '#/lib/i18n'
import { parseWholeNumber, type FieldError, type InstanceSettings } from './settings-form'

export type EmailSettings = InstanceSettings['email']
export type EmailDelivery = EmailSettings['delivery']
export type EmailTemplate = EmailSettings['templates'][number]
export type EmailTemplateLocale = EmailTemplate['locales'][number]

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

/** The mutation input for `draft`, or the fields that need attention. */
export function emailDeliveryInput(
  delivery: EmailDelivery,
  draft: EmailDeliveryDraft,
):
  | { input: Omit<UpdateEmailDeliverySettingsInput, 'clientMutationId'> }
  | { errors: Partial<Record<EmailDeliveryField, FieldError>> } {
  const errors: Partial<Record<EmailDeliveryField, FieldError>> = {}
  const required = (field: EmailDeliveryField, value: string) => {
    if (!value.trim()) errors[field] = { key: 'settingsEmailRequired' }
  }
  const port = parseWholeNumber(draft.port, delivery.portRange)
  if ('error' in port) errors.port = port.error
  if (draft.enabled || draft.host.trim()) required('host', draft.host)
  if (draft.enabled || draft.senderAddress.trim()) {
    required('senderAddress', draft.senderAddress)
    if (draft.senderAddress.trim() && !/^[^\s@]+@[^\s@]+$/u.test(draft.senderAddress.trim())) {
      errors.senderAddress = { key: 'settingsEmailInvalidAddress' }
    }
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
      enabled: draft.enabled,
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
}

export interface EmailTemplateContentDraft {
  subject: string
  html: string
  text: string
}

/** One locale of a template being edited. */
export interface EmailTemplateLocaleDraft extends EmailTemplateContentDraft {
  locale: string
  customized: boolean
}

export function emailTemplateDraft(template: EmailTemplate): EmailTemplateLocaleDraft[] {
  return template.locales.map((locale) => ({
    locale: locale.locale,
    customized: locale.customized,
    subject: locale.subject,
    html: locale.html,
    text: locale.text,
  }))
}

/** The built-in content of `locale`. */
export function defaultContent(template: EmailTemplate, locale: string): EmailTemplateContentDraft {
  const found = template.locales.find((entry) => entry.locale === locale)
  return {
    subject: found?.defaultSubject ?? '',
    html: found?.defaultHtml ?? '',
    text: found?.defaultText ?? '',
  }
}

/** The content a locale sends: its own when customized, else the built-in one. */
export function effectiveContent(
  template: EmailTemplate,
  draft: EmailTemplateLocaleDraft,
): EmailTemplateContentDraft {
  return draft.customized ? draft : defaultContent(template, draft.locale)
}

export function emailTemplateInput(
  template: EmailTemplate,
  drafts: EmailTemplateLocaleDraft[],
): Omit<UpdateEmailTemplateInput, 'clientMutationId'> {
  return {
    kind: template.kind,
    locales: drafts
      .filter((draft) => draft.customized)
      .map((draft) => ({
        locale: draft.locale,
        content: { subject: draft.subject, html: draft.html, text: draft.text },
      })),
    expectedVersion: template.version,
  }
}

/**
 * Server field errors of a template save, by locale and part:
 * `locales.<index>.content.<part>` becomes `{ [locale]: { [part]: message } }`.
 */
export function templateFieldErrors(
  drafts: EmailTemplateLocaleDraft[],
  fields: Record<string, string>,
): Record<string, Partial<Record<keyof EmailTemplateContentDraft, string>>> {
  const customized = drafts.filter((draft) => draft.customized)
  const result: Record<string, Partial<Record<keyof EmailTemplateContentDraft, string>>> = {}
  for (const [path, message] of Object.entries(fields)) {
    const match = /(?:^|\.)locales\.(\d+)\.content\.(subject|html|text)$/u.exec(path)
    if (!match) continue
    const locale = customized[Number(match[1])]?.locale
    if (!locale) continue
    const part = match[2] as keyof EmailTemplateContentDraft
    result[locale] = { ...result[locale], [part]: message }
  }
  return result
}
