import { QueryClient } from '@tanstack/react-query'

/**
 * Conservative defaults for a management console: a failed read is shown to
 * the operator instead of being retried behind the authentication flow, and a
 * mount always revalidates so optimistic-lock versions stay current.
 */
export function createQueryClient(): QueryClient {
  return new QueryClient({
    defaultOptions: {
      queries: {
        retry: false,
        staleTime: 0,
        refetchOnWindowFocus: false,
      },
      mutations: { retry: false },
    },
  })
}

/** Browser-wide client used by the mounted application. */
export const queryClient = createQueryClient()
