import { BROWSER_LOCALE_VALUE, type Locale } from '#/lib/i18n'

export { BROWSER_LOCALE_VALUE }

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
