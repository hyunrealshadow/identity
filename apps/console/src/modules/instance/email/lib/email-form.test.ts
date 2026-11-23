import { describe, expect, it } from 'vitest'

import {
  addTemplateTranslation,
  customizeEmailTemplate,
  emailDeliveryDraft,
  emailDeliveryInput,
  emailTemplateInput,
  removeTemplateTranslation,
  templateContent,
  templateFieldErrors,
  updateTemplateContent,
  type EmailDelivery,
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

  it('requires a server and sender only while sending is on', () => {
    const off = { ...emailDeliveryDraft(delivery), enabled: false, host: '', senderAddress: '' }
    expect('input' in emailDeliveryInput(delivery, off)).toBe(true)
    expect(emailDeliveryInput(delivery, { ...off, enabled: true })).toEqual({
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
