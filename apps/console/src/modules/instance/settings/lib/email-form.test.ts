import { describe, expect, it } from 'vitest'

import {
  emailDeliveryDraft,
  emailDeliveryInput,
  emailTemplateInput,
  templateFieldErrors,
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
  const template: EmailTemplate = {
    kind: 'SIGN_IN_CODE',
    variables: ['code'],
    version: 't1',
    locales: ['en-US', 'zh-CN'].map((locale) => ({
      locale,
      customized: false,
      subject: 'S',
      html: 'H',
      text: 'T',
      defaultSubject: 'S',
      defaultHtml: 'H',
      defaultText: 'T',
    })),
  }

  it('sends only customized locales and maps their errors back by locale', () => {
    const drafts = [
      { locale: 'en-US', customized: false, subject: 'S', html: 'H', text: 'T' },
      { locale: 'zh-CN', customized: true, subject: '{{ code }}', html: '{% if %}', text: 'T' },
    ]
    expect(emailTemplateInput(template, drafts)).toEqual({
      kind: 'SIGN_IN_CODE',
      locales: [
        { locale: 'zh-CN', content: { subject: '{{ code }}', html: '{% if %}', text: 'T' } },
      ],
      expectedVersion: 't1',
    })
    expect(
      templateFieldErrors(drafts, { 'input.locales.0.content.html': 'broken' }),
    ).toEqual({ 'zh-CN': { html: 'broken' } })
  })
})
