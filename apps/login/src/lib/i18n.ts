import { createIntl, createIntlCache } from 'react-intl'

import enUS from './locales/en-US'
import zhCN from './locales/zh-CN'

export const supportedLocales = ['en-US', 'zh-CN'] as const

export type Locale = (typeof supportedLocales)[number]
export type MessageKey = keyof typeof enUS

export const defaultLocale: Locale = 'en-US'

const messages: Record<Locale, Record<MessageKey, string>> = {
  'en-US': enUS,
  'zh-CN': zhCN,
}

const intlCache = createIntlCache()
const formatters = Object.fromEntries(
  supportedLocales.map((locale) => [
    locale,
    createIntl(
      {
        locale,
        defaultLocale,
        messages: messages[locale],
      },
      intlCache,
    ),
  ]),
) as Record<Locale, ReturnType<typeof createIntl>>

function matchLocale(value: string | undefined): Locale | undefined {
  const normalized = value?.trim().toLowerCase()
  if (!normalized) return undefined
  if (normalized === 'zh' || normalized.startsWith('zh-')) return 'zh-CN'
  if (normalized === 'en' || normalized.startsWith('en-')) return 'en-US'
  return undefined
}

export function resolveLocale(options: {
  uiLocales?: readonly string[]
  acceptLanguage?: string | null
} = {}): Locale {
  for (const candidate of options.uiLocales ?? []) {
    const locale = matchLocale(candidate)
    if (locale) return locale
  }
  for (const part of options.acceptLanguage?.split(',') ?? []) {
    const locale = matchLocale(part.split(';')[0])
    if (locale) return locale
  }
  return defaultLocale
}

export function translate(
  locale: Locale,
  key: MessageKey,
  values: Record<string, string | number> = {},
) {
  return formatters[locale].formatMessage(
    { id: key, defaultMessage: enUS[key] },
    values,
  ) as string
}

export function scopeDescription(locale: Locale, name: string, fallback: string) {
  const key = `scope_${name}` as MessageKey
  return key in messages[locale] ? translate(locale, key) : fallback
}
