import { useMemo } from 'react'

import {
  ConsoleClientKeyCoverageDocument,
  type ConsoleClientKeyCoverageQuery,
  type ConsoleClientKeyCoverageQueryVariables,
} from '#/generated/graphql'
import { fieldAffordance } from '#/lib/graphql/affordances'
import { useConsoleQuery } from '#/lib/graphql/use-console-query'
import { useWorkspace } from '#/lib/workspace'

type CoverageClient = NonNullable<ConsoleClientKeyCoverageQuery['client']>

/** What the client's credentials can serve, and how it authenticates. */
export interface ClientKeyCoverage {
  coverage: CoverageClient['keyCoverage']
  authMethods: CoverageClient['tokenEndpointAuthMethods']
}

/**
 * The client's key coverage, fetched only for someone who may read its
 * credentials. Without that access, or until it loads, coverage is `null`:
 * unknown, which the settings must not present as "no key".
 */
export function useClientKeyCoverage(clientId: string): ClientKeyCoverage | null {
  const workspace = useWorkspace()
  const readable = fieldAffordance(
    workspace.data?.effectivePermissions,
    'Client',
    'keyCoverage',
  )
  const variables = useMemo<ConsoleClientKeyCoverageQueryVariables | null>(
    () => (readable ? { id: clientId } : null),
    [readable, clientId],
  )
  const query = useConsoleQuery<
    ConsoleClientKeyCoverageQuery,
    ConsoleClientKeyCoverageQueryVariables
  >(ConsoleClientKeyCoverageDocument, variables, readable, 'missing_client_key_coverage')
  const client = query.data?.client
  return client
    ? { coverage: client.keyCoverage, authMethods: client.tokenEndpointAuthMethods }
    : null
}
