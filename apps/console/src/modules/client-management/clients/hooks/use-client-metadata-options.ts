import { useMemo } from 'react'

import {
  ConsoleClientMetadataOptionsDocument,
  type ConsoleClientMetadataOptionsQuery,
  type ConsoleClientMetadataOptionsQueryVariables,
} from '#/generated/graphql'
import { useConsoleQuery } from '#/lib/graphql/use-console-query'

export type ClientMetadataOptions =
  ConsoleClientMetadataOptionsQuery['clientMetadataOptions']

/**
 * Values the advanced settings may choose from, as the provider publishes
 * them. Until they arrive, selects offer only the stored value and the
 * provider default.
 */
export function useClientMetadataOptions() {
  const variables = useMemo<ConsoleClientMetadataOptionsQueryVariables>(() => ({}), [])
  const query = useConsoleQuery<
    ConsoleClientMetadataOptionsQuery,
    ConsoleClientMetadataOptionsQueryVariables
  >(
    ConsoleClientMetadataOptionsDocument,
    variables,
    true,
    'missing_client_metadata_options',
  )
  return {
    options: query.data?.clientMetadataOptions ?? null,
    status: query.status,
    errors: query.errors,
    requestId: query.requestId,
    traceId: query.traceId,
    refresh: () => query.refresh(),
  }
}
