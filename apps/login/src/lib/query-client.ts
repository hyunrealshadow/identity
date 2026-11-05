import { QueryClient } from '@tanstack/react-query'

/**
 * Account reads are cheap and change through explicit actions, so a short
 * freshness window avoids refetching on every account tab navigation while a
 * failed read is still surfaced instead of retried behind the OAuth flow.
 */
export function createQueryClient(): QueryClient {
  return new QueryClient({
    defaultOptions: {
      queries: { retry: false, staleTime: 30_000 },
      mutations: { retry: false },
    },
  })
}
