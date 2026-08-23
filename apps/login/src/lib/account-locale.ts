import type { Locale } from './i18n'

export const BROWSER_LOCALE_VALUE = 'browser'

export function resolveAccountLocale(
  preference: string | undefined,
  browserLocale: Locale,
): Locale {
  return preference === 'en-US' || preference === 'zh-CN'
    ? preference
    : browserLocale
}

export function localePreferenceValue(value: string | undefined) {
  return value === BROWSER_LOCALE_VALUE || !value ? null : value
}
