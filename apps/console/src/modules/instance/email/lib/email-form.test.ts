import { describe, expect, it } from 'vitest'

import {
  addTemplateTranslation,
  customizeEmailTemplate,
  emailDeliveryDirty,
  emailDeliveryDraft,
  emailDeliveryInput,
  emailPolicyDraft,
  emailPolicyInput,
  emailTemplateInput,
  removeTemplateTranslation,
  templateContent,
  templateFieldErrors,
  updateTemplateContent,
  type EmailDelivery,
  type EmailPolicy,
  type EmailTemplate,
} from './email-form'

const delivery: EmailDelivery = {
  enabled: true,
  host: 'smtp.example.com',
  port: 587,
  portRange: { min: 1, max: 65535 },
  security: 'START_TLS',
  senderAddress: 'identity@example.com',
  senderName: null,
  authentication: {
    method: 'PASSWORD',
    username: 'mailer',
    passwordSet: true,
    tokenEndpoint: null,
    clientId: null,
    clientSecretSet: false,
    grant: null,
    refreshTokenSet: false,
    scope: null,
  },
  configured: true,
  version: 'v1',
}

describe('email delivery form', () => {
  it('keeps a stored password when the field is left empty', () => {
    const result = emailDeliveryInput(delivery, emailDeliveryDraft(delivery))
    expect(result).toMatchObject({
      input: {
        enabled: true,
        authentication: { method: 'PASSWORD', username: 'mailer', password: null },
        expectedVersion: 'v1',
      },
    })
  })

  it('asks for the secrets of a newly chosen method', () => {
    const draft = {
      ...emailDeliveryDraft(delivery),
      method: 'XOAUTH2' as const,
      username: 'mailer@example.com',
    }
    expect(emailDeliveryInput(delivery, draft)).toEqual({
      errors: {
        tokenEndpoint: { key: 'settingsEmailRequired' },
        clientId: { key: 'settingsEmailRequired' },
        refreshToken: { key: 'settingsEmailRequired' },
      },
    })

    const clientCredentials = emailDeliveryInput(delivery, {
      ...draft,
      tokenEndpoint: 'https://oauth2.example.com/token',
      clientId: 'client',
      grant: 'CLIENT_CREDENTIALS',
    })
    expect(clientCredentials).toMatchObject({
      input: {
        authentication: {
          method: 'XOAUTH2',
          grant: 'CLIENT_CREDENTIALS',
          refreshToken: null,
          clientSecret: null,
        },
      },
    })
  })

  it('preserves stored configuration when turning delivery off and ignores hidden edits', () => {
    const disabledDraft = {
      ...emailDeliveryDraft(delivery),
      enabled: false,
      host: '',
      senderAddress: 'invalid',
      port: '0',
    }
    expect(emailDeliveryDirty(delivery, disabledDraft)).toBe(true)
    expect(emailDeliveryDirty({ ...delivery, enabled: false }, disabledDraft)).toBe(false)
    expect(emailDeliveryInput(delivery, disabledDraft)).toEqual({
      input: {
        enabled: false,
        host: 'smtp.example.com',
        port: 587,
        security: 'START_TLS',
        senderAddress: 'identity@example.com',
        senderName: null,
        authentication: {
          method: 'PASSWORD',
          username: 'mailer',
          password: null,
        },
        expectedVersion: 'v1',
      },
    })
  })

  it('requires a server and sender when enabling delivery', () => {
    const emptyEnabled = {
      ...emailDeliveryDraft(delivery),
      enabled: true,
      host: '',
      senderAddress: '',
      method: 'NONE' as const,
    }
    expect(emailDeliveryInput(delivery, emptyEnabled)).toEqual({
      errors: {
        host: { key: 'settingsEmailRequired' },
        senderAddress: { key: 'settingsEmailRequired' },
      },
    })
  })
})

describe('email template form', () => {
  const page = (value: string) => ({ subject: value, html: `<p>${value}</p>` })
  const builtIn = {
    default: page('Hello'),
    translations: [{ locale: 'zh-CN', content: page('你好') }],
  }
  const template: EmailTemplate = {
    kind: 'SIGN_IN_CODE',
    variables: ['code'],
    previewScenarios: ['SIGN_IN_CODE_WITH_APPLICATION', 'SIGN_IN_CODE_WITHOUT_APPLICATION'],
    customized: false,
    version: 't1',
    content: builtIn,
    builtIn,
  }

  it('customizes a copy of the built-in template and resets with null content', () => {
    const draft = customizeEmailTemplate(template)
    expect(draft).toEqual({ customized: true, ...builtIn })
    expect(emailTemplateInput(template, { ...draft, customized: false })).toEqual({
      kind: 'SIGN_IN_CODE',
      content: null,
      expectedVersion: 't1',
    })
  })

  it('adds, edits and removes translations in language order', () => {
    let draft = customizeEmailTemplate(template)
    draft = addTemplateTranslation(draft, 'fr', draft.default)
    draft = addTemplateTranslation(draft, 'fr', page('ignored'))
    draft = updateTemplateContent(draft, 'fr', { subject: 'Bonjour' })
    expect(draft.translations.map((translation) => translation.locale)).toEqual(['fr', 'zh-CN'])
    expect(templateContent(draft, 'fr')?.subject).toBe('Bonjour')
    expect(templateContent(draft, null)?.subject).toBe('Hello')

    expect(emailTemplateInput(template, draft).content?.translations).toEqual([
      { locale: 'fr', content: { ...page('Hello'), subject: 'Bonjour' } },
      { locale: 'zh-CN', content: page('你好') },
    ])
    expect(removeTemplateTranslation(draft, 'fr').translations).toHaveLength(1)
  })

  it('maps server field errors back to the language and part', () => {
    const draft = addTemplateTranslation(customizeEmailTemplate(template), 'fr', page('Salut'))
    expect(
      templateFieldErrors(draft, {
        'input.content.default.subject': 'missing',
        'input.content.translations.0.content.html': 'broken',
        'input.content.translations.1.locale': 'duplicate',
      }),
    ).toEqual({
      '': { subject: 'missing' },
      fr: { html: 'broken' },
      'zh-CN': { locale: 'duplicate' },
    })
  })
})

const emailPolicy: EmailPolicy = {
  signInCodeLifetimeMinutes: 10,
  signInCodeLifetimeMinutesRange: { min: 1, max: 60 },
  passwordResetLifetimeMinutes: 15,
  passwordResetLifetimeMinutesRange: { min: 5, max: 120 },
  registrationLifetimeMinutes: 15,
  registrationLifetimeMinutesRange: { min: 5, max: 120 },
  emailVerificationLifetimeHours: 24,
  emailVerificationLifetimeHoursRange: { min: 1, max: 168 },
  userInvitationLifetimeDays: 7,
  userInvitationLifetimeDaysRange: { min: 1, max: 30 },
  resendIntervalSeconds: 60,
  resendIntervalSecondsRange: { min: 15, max: 600 },
  loginMaxSends: 5,
  loginMaxSendsRange: { min: 1, max: 20 },
  verificationMaxSends: 5,
  verificationMaxSendsRange: { min: 1, max: 20 },
  verificationSendWindowHours: 24,
  verificationSendWindowHoursRange: { min: 1, max: 168 },
  version: 'p1',
}

describe('email policy form', () => {
  it('validates ranges and builds policy inputs', () => {
    const valid = emailPolicyInput(emailPolicy, {
      ...emailPolicyDraft(emailPolicy),
      resendIntervalSeconds: '90',
      loginMaxSends: '8',
    })
    expect(valid).toEqual({
      input: {
        signInCodeLifetimeMinutes: 10,
        passwordResetLifetimeMinutes: 15,
        registrationLifetimeMinutes: 15,
        emailVerificationLifetimeHours: 24,
        userInvitationLifetimeDays: 7,
        resendIntervalSeconds: 90,
        loginMaxSends: 8,
        verificationMaxSends: 5,
        verificationSendWindowHours: 24,
        expectedVersion: 'p1',
      },
    })

    const invalid = emailPolicyInput(emailPolicy, {
      ...emailPolicyDraft(emailPolicy),
      signInCodeLifetimeMinutes: '0',
      resendIntervalSeconds: '10',
    })
    expect(invalid).toEqual({
      errors: {
        signInCodeLifetimeMinutes: { key: 'settingsOutOfRange', values: { min: 1, max: 60 } },
        resendIntervalSeconds: { key: 'settingsOutOfRange', values: { min: 15, max: 600 } },
      },
    })
  })
})
