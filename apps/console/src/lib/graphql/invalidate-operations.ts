import { useQueryClient } from '@tanstack/react-query'
import { useCallback } from 'react'

import { useSessionVersion } from '#/lib/auth/session-version'
import { useLocale } from '#/lib/i18n'
import {
  consoleQueryKeys,
  operationNameOf,
  operationOfKey,
  type AnyDocument,
} from './query-keys'

/**
 * Marks the given read documents stale and refetches the mounted ones.
 *
 * Invalidating one document covers every variable combination of that read
 * without touching another session's or locale's cache entry. Documents are
 * passed instead of names, so a renamed or mistyped read fails to compile.
 */
export function useInvalidateOperations() {
  const client = useQueryClient()
  const sessionVersion = useSessionVersion()
  const { locale } = useLocale()

  return useCallback(
    (documents: readonly AnyDocument[]) => {
      const names = new Set(documents.map(operationNameOf))
      // One pass over the cache: every variable combination of each named
      // read, limited to this session and locale.
      return client.invalidateQueries({
        queryKey: consoleQueryKeys.scope(sessionVersion, locale),
        predicate: (query) => names.has(operationOfKey(query.queryKey) ?? ''),
      })
    },
    [client, locale, sessionVersion],
  )
}
