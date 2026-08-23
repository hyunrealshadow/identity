import { describe, expect, it } from 'vitest'

import {
  BROWSER_LOCALE_VALUE,
  localePreferenceValue,
  resolveAccountLocale,
} from './account-locale'

describe('account locale preference', () => {
  it('uses the saved supported locale instead of the browser locale', () => {
    expect(resolveAccountLocale('en-US', 'zh-CN')).toBe('en-US')
    expect(resolveAccountLocale('zh-CN', 'en-US')).toBe('zh-CN')
  })

  it('falls back to the browser when no supported preference is saved', () => {
    expect(resolveAccountLocale(undefined, 'zh-CN')).toBe('zh-CN')
    expect(resolveAccountLocale('invalid', 'en-US')).toBe('en-US')
  })

  it('clears the stored preference for the browser option', () => {
    expect(localePreferenceValue(BROWSER_LOCALE_VALUE)).toBeNull()
    expect(localePreferenceValue('zh-CN')).toBe('zh-CN')
  })
})
