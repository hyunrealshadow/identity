import { useMemo } from 'react'

import {
  ConsoleClientMetadataDocument,
  type ConsoleClientMetadataQuery,
  type ConsoleClientMetadataQueryVariables,
} from '#/generated/graphql'
import type { GraphQLFailure, GraphQLIssue } from '#/lib/graphql/transport'
import { useConsoleQuery } from '#/lib/graphql/use-console-query'

export type ClientMetadata = NonNullable<
  ConsoleClientMetadataQuery['instanceMetadata']
>

export interface ClientMetadataState {
  status: 'loading' | 'ready' | 'error'
  data: ClientMetadata | null
  errors: GraphQLIssue[]
  failure?: GraphQLFailure
  requestId?: string
  traceId?: string
  refresh: () => Promise<void>
}

/**
 * Endpoint URLs this client uses, taken from the provider's discovery data so
 * the tab cannot drift from what the well-known documents publish.
 */
export function useClientMetadata(): ClientMetadataState {
  const variables = useMemo<ConsoleClientMetadataQueryVariables>(() => ({}), [])
  const query = useConsoleQuery<
    ConsoleClientMetadataQuery,
    ConsoleClientMetadataQueryVariables
  >(
    ConsoleClientMetadataDocument,
    variables,
    true,
    'missing_instance_metadata',
  )
  const metadata = query.data?.instanceMetadata ?? null
  const missing = query.status === 'ready' && metadata === null

  return {
    status: missing ? 'error' : query.status === 'idle' ? 'loading' : query.status,
    data: metadata,
    errors: query.errors,
    failure: query.failure,
    requestId: query.requestId,
    traceId: query.traceId,
    refresh: async () => {
      await query.refresh()
    },
  }
}
