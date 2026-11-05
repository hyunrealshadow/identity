import { createContext, useContext } from 'react'

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
