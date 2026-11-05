import { useQuery } from '@tanstack/react-query'

import {
  ConsoleAuthorizationLabelsDocument,
  type ConsoleAuthorizationLabelsQuery,
  type ConsoleAuthorizationLabelsQueryVariables,
} from '#/generated/graphql'
import { useGraphQL } from '#/lib/graphql/use-graphql'

export interface AuthorizationLabels {
  nodes: ConsoleAuthorizationLabelsQuery['nodes']
  failed: boolean
}

const EMPTY: AuthorizationLabels = { nodes: [], failed: false }
const LABEL_BATCH_SIZE = 100

/** Resolve each distinct label once, keeping every request inside the node lookup limit. */
export function useAuthorizationLabels(ids: readonly string[]): AuthorizationLabels {
  const request = useGraphQL()

  const query = useQuery({
    queryKey: ['console', 'AuthorizationLabels', ids],
    retry: false,
    staleTime: 0,
    queryFn: async ({ signal }): Promise<AuthorizationLabels> => {
      const nodes: ConsoleAuthorizationLabelsQuery['nodes'] = []
      let failed = false
      for (let offset = 0; offset < ids.length; offset += LABEL_BATCH_SIZE) {
        const variables: ConsoleAuthorizationLabelsQueryVariables = {
          ids: ids.slice(offset, offset + LABEL_BATCH_SIZE),
        }
        const result = await request<
          ConsoleAuthorizationLabelsQuery,
          ConsoleAuthorizationLabelsQueryVariables
        >(
          ConsoleAuthorizationLabelsDocument,
          variables,
          'ConsoleAuthorizationLabels',
          { signal },
        )
        if (signal.aborted) {
          throw new DOMException('The label lookup was aborted.', 'AbortError')
        }
        nodes.push(...(result.data?.nodes ?? []))
        failed ||= result.data === null || result.errors.length > 0
      }
      return { nodes, failed }
    },
  })

  return query.data ?? EMPTY
}
