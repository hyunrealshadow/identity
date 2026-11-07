import { useTheme } from '@heroui/react'
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

/** The theme an account preference selects; no preference follows the system. */
export function themeFromAccount(value: string | null | undefined): 'light' | 'dark' | 'system' {
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
  const { setTheme } = useTheme()
  const query = useQuery({
    queryKey: consoleQueryKeys.read(sessionVersion, locale, ConsoleAccountThemeDocument, {}),
    enabled: status === 'authenticated',
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
    if (theme) setTheme(theme)
  }, [setTheme, theme])

  return null
}
