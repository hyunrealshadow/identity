import { QueryClient } from '@tanstack/react-query'

/**
 * A failed read is surfaced instead of retried behind the OAuth flow. Each
 * read declares its own freshness next to its key in `queryOptions`, so the
 * client keeps no shared `staleTime` that could silently diverge from it.
 */
export function createQueryClient(): QueryClient {
  return new QueryClient({
    defaultOptions: {
      queries: { retry: false },
      mutations: { retry: false },
    },
  })
}
