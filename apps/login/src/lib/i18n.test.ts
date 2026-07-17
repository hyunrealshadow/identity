import { describe, expect, it } from 'vitest'

import { resolveLocale, translate } from './i18n'

describe('resolveLocale', () => {
  it('defaults to English', () => expect(resolveLocale()).toBe('en-US'))
  it('uses the browser language', () => {
    expect(resolveLocale({ acceptLanguage: 'zh-CN,zh;q=0.9' })).toBe('zh-CN')
    expect(resolveLocale({ acceptLanguage: 'en-US,en;q=0.9' })).toBe('en-US')
  })
  it('gives OIDC ui_locales priority', () => {
    expect(resolveLocale({ uiLocales: ['zh-CN'], acceptLanguage: 'en-US' })).toBe('zh-CN')
  })
  it('ignores unsupported locales', () => {
    expect(resolveLocale({ uiLocales: ['se'], acceptLanguage: 'en-US' })).toBe('en-US')
  })
})

it('interpolates translated messages', () => {
  expect(translate('en-US', 'consentDescription', { client: 'Portal' })).toBe('Portal wants to access your account.')
})
