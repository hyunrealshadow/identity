import { useQueryClient } from '@tanstack/react-query'
import { useCallback } from 'react'

import { useSessionVersion } from '#/lib/auth/session-version'
import { useLocale } from '#/lib/i18n'

/**
 * Marks the named console operations stale and refetches the mounted ones.
 *
 * Keys are built by `useConsoleQuery` as
 * `['console', sessionVersion, locale, operation, variables]`, so invalidating
 * one operation covers every variable combination of that read without
 * touching another session's cache entry.
 */
export function useInvalidateOperations() {
  const client = useQueryClient()
  const sessionVersion = useSessionVersion()
  const { locale } = useLocale()

  return useCallback(
    async (operations: readonly string[]) => {
      await Promise.all(
        operations.map((operation) =>
          client.invalidateQueries({
            queryKey: ['console', sessionVersion, locale, operation],
          }),
        ),
      )
    },
    [client, locale, sessionVersion],
  )
}
