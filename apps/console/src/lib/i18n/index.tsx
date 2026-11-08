import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useRef,
  useState,
  type ReactNode,
} from 'react'
import { IntlProvider, createIntl, createIntlCache, useIntl } from 'react-intl'

import enUS from '#/lib/locales/en-US'
import zhCN from '#/lib/locales/zh-CN'
import { resolveTimeZone } from '#/lib/time-zone'

export const supportedLocales = ['en-US', 'zh-CN'] as const
export type Locale = (typeof supportedLocales)[number]
export type LocalePreference = Locale | 'browser'
export type MessageKey = keyof typeof enUS
export type MessageValues = Record<string, string | number>

export const defaultLocale: Locale = 'en-US'

const messages: Record<Locale, Record<MessageKey, string>> = {
  'en-US': enUS,
  'zh-CN': zhCN,
}

const intlCache = createIntlCache()
const formatters = Object.fromEntries(
  supportedLocales.map((locale) => [
    locale,
    createIntl({ locale, defaultLocale, messages: messages[locale] }, intlCache),
  ]),
) as Record<Locale, ReturnType<typeof createIntl>>

export function isLocale(value: unknown): value is Locale {
  return value === 'en-US' || value === 'zh-CN'
}

export function matchLocale(value: string | null | undefined): Locale | undefined {
  const normalized = value?.trim().toLowerCase()
  if (!normalized) return undefined
  if (normalized === 'zh' || normalized.startsWith('zh-')) return 'zh-CN'
  if (normalized === 'en' || normalized.startsWith('en-')) return 'en-US'
  return undefined
}

export function resolveBrowserLocale(
  languages: readonly string[] = typeof navigator === 'undefined'
    ? []
    : (navigator.languages ?? [navigator.language]),
): Locale {
  for (const language of languages) {
    const locale = matchLocale(language)
    if (locale) return locale
  }
  return defaultLocale
}

/**
 * Central account preference resolution, matching the account center and
 * Login: a supported saved locale wins, while null, missing and unsupported
 * values fall back to the current browser language. Console-local storage is
 * deliberately not consulted.
 */
export function resolveAccountLocale(
  accountLocale: string | null | undefined,
  browserLocale: Locale = resolveBrowserLocale(),
): Locale {
  return isLocale(accountLocale) ? accountLocale : browserLocale
}

export function translate(
  locale: Locale,
  key: MessageKey,
  values: MessageValues = {},
): string {
  return formatters[locale].formatMessage({ id: key, defaultMessage: enUS[key] }, values)
}

interface LocaleContextValue {
  locale: Locale
  timeZone: string
  applyAccountTimeZone: (preference: string | null | undefined) => void
  preference: LocalePreference
  /** Legacy selector hook. Never persisted and superseded by account preference. */
  setLocale: (preference: LocalePreference) => void
  /** Applies the validated account/JWT preference; null clears any override. */
  applyAccountLocale: (accountLocale: string | null | undefined) => void
  t: (key: MessageKey, values?: MessageValues) => string
}

interface LocaleState {
  preference: LocalePreference
  locale: Locale
}

const LocaleContext = createContext<LocaleContextValue | null>(null)

/**
 * Last committed effective locale. Error boundaries and other components
 * rendered outside the provider must follow this value instead of consulting
 * obsolete local storage.
 */
let activeLocale: Locale | null = null

function browserState(): LocaleState {
  return { preference: 'browser', locale: resolveBrowserLocale() }
}

function initialState(initialLocale?: string | null): LocaleState {
  if (isLocale(initialLocale)) return { preference: initialLocale, locale: initialLocale }
  return browserState()
}

/** Error boundaries may render outside the locale provider. */
export function resolveCurrentLocale(): Locale {
  return activeLocale ?? resolveBrowserLocale()
}

export function LocaleProvider({
  children,
  initialLocale,
  initialTimeZone,
}: {
  children: ReactNode
  /** Explicit host/fixture seeding. Production derives the locale from the account. */
  initialLocale?: string | null
  initialTimeZone?: string | null
}) {
  const accountTimeZone = useRef(initialTimeZone)
  const [timeZone, setTimeZone] = useState(() => resolveTimeZone(initialTimeZone))
  const applyAccountTimeZone = useCallback((preference: string | null | undefined) => {
    accountTimeZone.current = preference
    setTimeZone(resolveTimeZone(preference))
  }, [])

  useEffect(() => {
    const updateTimeZone = () => setTimeZone(resolveTimeZone(accountTimeZone.current))
    window.addEventListener('focus', updateTimeZone)
    return () => window.removeEventListener('focus', updateTimeZone)
  }, [])
  const [state, setState] = useState<LocaleState>(() => {
    const next = initialState(initialLocale)
    activeLocale = next.locale
    return next
  })

  const applyAccountLocale = useCallback(
    (accountLocale: string | null | undefined) => {
      const next: LocaleState = isLocale(accountLocale)
        ? { preference: accountLocale, locale: accountLocale }
        : browserState()
      activeLocale = next.locale
      setState((previous) =>
        previous.preference === next.preference && previous.locale === next.locale
          ? previous
          : next,
      )
    },
    [],
  )

  const setLocale = useCallback((preference: LocalePreference) => {
    const next: LocaleState =
      preference === 'browser'
        ? browserState()
        : { preference, locale: preference }
    activeLocale = next.locale
    setState((previous) =>
      previous.preference === next.preference && previous.locale === next.locale
        ? previous
        : next,
    )
  }, [])

  const t = useCallback(
    (key: MessageKey, values: MessageValues = {}) => translate(state.locale, key, values),
    [state.locale],
  )

  useEffect(() => {
    activeLocale = state.locale
    document.documentElement.lang = state.locale
    document.documentElement.dir = 'ltr'
  }, [state.locale])

  // Only browser mode follows live browser-language changes. A saved account
  // preference keeps winning until the account setting itself changes.
  useEffect(() => {
    const onLanguageChange = () => {
      setState((previous) => {
        if (previous.preference !== 'browser') return previous
        const locale = resolveBrowserLocale()
        activeLocale = locale
        return previous.locale === locale ? previous : { preference: 'browser', locale }
      })
    }
    window.addEventListener('languagechange', onLanguageChange)
    return () => window.removeEventListener('languagechange', onLanguageChange)
  }, [])

  const value = useMemo<LocaleContextValue>(
    () => ({
      locale: state.locale,
      timeZone,
      applyAccountTimeZone,
      preference: state.preference,
      setLocale,
      applyAccountLocale,
      t,
    }),
    [applyAccountLocale, applyAccountTimeZone, setLocale, state.locale, state.preference, t, timeZone],
  )

  return (
    <LocaleContext.Provider value={value}>
        <IntlProvider
          locale={state.locale}
          timeZone={timeZone}
          defaultLocale={defaultLocale}
          messages={messages[state.locale]}
        >
          {children}
        </IntlProvider>
    </LocaleContext.Provider>
  )
}

export function useLocale(): LocaleContextValue {
  const value = useContext(LocaleContext)
  if (!value) throw new Error('useLocale must be used inside LocaleProvider')
  return value
}

export function useTranslator() {
  const intl = useIntl()
  const { locale } = useLocale()
  return useCallback(
    (key: MessageKey, values: MessageValues = {}) =>
      intl.formatMessage({ id: key, defaultMessage: enUS[key] }, values),
    [intl, locale],
  )
}
