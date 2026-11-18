import type { QueryClient } from '@tanstack/react-query'
import { createContext, useCallback, useContext, useState } from 'react'

/**
 * Increments whenever a new usable session replaces the previous one. Query
 * keys include it so a cached read can never be rendered for its successor,
 * even before the previous cache entry is collected.
 *
 * The default keeps component tests that mock the request path from needing a
 * full authentication provider.
 */
export const SessionVersionContext = createContext(0)

export function useSessionVersion(): number {
  return useContext(SessionVersionContext)
}

/**
 * The session version and the transition to the next one. The read cache is
 * emptied before the version changes, never after: clearing a cache that
 * already holds the new session's first reads cancels them silently and
 * leaves every mounted page loading forever.
 */
export function useSessionVersionCounter(client: QueryClient): readonly [number, () => void] {
  const [version, setVersion] = useState(0)
  const replace = useCallback(() => {
    client.clear()
    setVersion((current) => current + 1)
  }, [client])
  return [version, replace] as const
}
