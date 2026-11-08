import { useQuery } from '@tanstack/react-query'
import { useEffect } from 'react'

import {
  ConsoleAccountThemeDocument,
  type ConsoleAccountThemeQuery,
  type ConsoleAccountThemeQueryVariables,
} from '#/generated/graphql'
import { useAuth } from '#/lib/auth/context'
import { consoleQueryKeys } from '#/lib/graphql/query-keys'
import { useGraphQL } from '#/lib/graphql/use-graphql'
import { useLocale } from '#/lib/i18n'
import { applyTheme, rememberTheme, type ThemePreference } from '#/lib/theme'

/** The theme an account preference selects; no preference follows the system. */
export function themeFromAccount(value: string | null | undefined): ThemePreference {
  return value === 'light' || value === 'dark' ? value : 'system'
}

/**
 * Applies the signed-in operator's account theme preference, like the locale
 * and time zone that arrive with the ID token. A failed read (for example a
 * session issued before the Console requested `account.read`) keeps the local
 * theme and never starts reauthentication.
 */
export function AccountThemeSync() {
  const { status, sessionVersion } = useAuth()
  const { locale } = useLocale()
  const request = useGraphQL()
  const query = useQuery({
    queryKey: consoleQueryKeys.read(sessionVersion, locale, ConsoleAccountThemeDocument, {}),
    enabled: status === 'authenticated',
    // The account center is a separate tab: pick up a preference changed there
    // when the operator returns to this one, without polling.
    refetchOnWindowFocus: true,
    queryFn: ({ signal }) =>
      request<ConsoleAccountThemeQuery, ConsoleAccountThemeQueryVariables>(
        ConsoleAccountThemeDocument,
        {},
        'ConsoleAccountTheme',
        { signal },
      ),
  })
  const account = query.data?.data?.account
  const theme = account ? themeFromAccount(account.theme) : null

  useEffect(() => {
    // A runtime configuration older than the `account.read` request is rejected
    // during preflight. Say so in development instead of silently keeping the
    // system palette.
    if (query.error && import.meta.env.DEV && import.meta.env.MODE !== 'test') {
      console.warn('[console] account theme is unavailable', query.error)
    }
  }, [query.error])

  useEffect(() => {
    if (!theme) return
    applyTheme(theme)
    rememberTheme(theme)
    if (theme !== 'system') return
    const media = window.matchMedia('(prefers-color-scheme: dark)')
    const followSystem = () => applyTheme('system')
    media.addEventListener('change', followSystem)
    return () => media.removeEventListener('change', followSystem)
  }, [theme])

  return null
}
