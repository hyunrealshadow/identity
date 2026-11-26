import { useQuery } from '@tanstack/react-query'
import { useCallback, useMemo } from 'react'

import {
  ConsoleClientScopesDocument,
  ConsoleProtocolScopesDocument,
  type ConsoleClientScopesQuery,
  type ConsoleClientScopesQueryVariables,
  type ConsoleProtocolScopesQuery,
  type ConsoleProtocolScopesQueryVariables,
} from '#/generated/graphql'
import { useSessionVersion } from '#/lib/auth/session-version'
import type { GraphQLRequester } from '#/lib/graphql/requester'
import type {
  GraphQLFailure,
  GraphQLIssue,
  GraphQLStepUp,
} from '#/lib/graphql/transport'
import { useGraphQL } from '#/lib/graphql/use-graphql'
import { useLocale } from '#/lib/i18n'

const PAGE_SIZE = 100
const MAX_SCOPE_PAGES = 200

export type ClientScopeEdge = NonNullable<
  ConsoleClientScopesQuery['client']
>['scopes']['edges'][number]

export type ProtocolScopeNode =
  ConsoleProtocolScopesQuery['scopes']['edges'][number]['node']

export interface ClientScopesSnapshot {
  status: 'idle' | 'loading' | 'ready' | 'error'
  client: { id: string; version: string } | null
  edges: ClientScopeEdge[]
  complete: boolean
  errors: GraphQLIssue[]
  failure?: GraphQLFailure
  requestId?: string
  traceId?: string
  stepUp?: GraphQLStepUp
  forbidden: boolean
  refreshing: boolean
  reload: () => Promise<void>
}

export interface ProtocolScopesSnapshot {
  status: 'idle' | 'loading' | 'ready' | 'error'
  items: ProtocolScopeNode[]
}

async function collectClientScopes(
  request: GraphQLRequester,
  clientId: string,
  signal: AbortSignal,
): Promise<Omit<ClientScopesSnapshot, 'status' | 'refreshing' | 'reload'>> {
  const edges: ClientScopeEdge[] = []
  const seen = new Set<string>()
  const collectedErrors: GraphQLIssue[] = []
  let clientMeta: { id: string; version: string } | null = null
  let after: string | undefined
  let loadedPages = 0
  let hasNextPage = true
  let requestId: string | undefined
  let traceId: string | undefined

  const fail = (
    extra: Partial<Omit<ClientScopesSnapshot, 'status' | 'refreshing' | 'reload'>>,
  ) => ({
    client: clientMeta,
    edges,
    complete: false,
    errors: collectedErrors,
    requestId,
    traceId,
    forbidden: false,
    ...extra,
  })

  while (hasNextPage) {
    if (loadedPages >= MAX_SCOPE_PAGES) {
      return fail({
        failure: {
          kind: 'invalid_response',
          code: 'client_scopes_page_limit',
        },
      })
    }
    const variables: ConsoleClientScopesQueryVariables = {
      id: clientId,
      orderBy: 'CODE_ASC',
      first: PAGE_SIZE,
      after,
    }
    const result = await request<
      ConsoleClientScopesQuery,
      ConsoleClientScopesQueryVariables
    >(ConsoleClientScopesDocument, variables, 'ConsoleClientScopes', { signal })
    if (signal.aborted) {
      throw new DOMException('The client scopes walk was aborted.', 'AbortError')
    }
    requestId = result.requestId
    traceId = result.traceId
    collectedErrors.push(...result.errors)

    const client = result.data?.client ?? null
    if (!client || result.errors.length > 0) {
      return fail({
        failure:
          result.failure ?? {
            kind: 'invalid_response',
            code: client ? 'client_scopes_partial_failure' : 'missing_client_scopes',
            requestId: result.requestId,
            traceId: result.traceId,
          },
        requestId: result.requestId,
        traceId: result.traceId,
        stepUp: result.stepUp,
        forbidden: result.forbidden,
      })
    }

    clientMeta = { id: client.id, version: client.version }
    for (const edge of client.scopes.edges) {
      if (!seen.has(edge.node.id)) {
        seen.add(edge.node.id)
        edges.push(edge)
      }
    }
    loadedPages += 1
    hasNextPage = client.scopes.pageInfo.hasNextPage
    const nextAfter = client.scopes.pageInfo.endCursor
    if (hasNextPage && !nextAfter) {
      return fail({
        failure: {
          kind: 'invalid_response',
          code: 'missing_client_scopes_cursor',
        },
      })
    }
    after = nextAfter ?? undefined

    if (result.failure && !result.partial) {
      return fail({
        failure: result.failure,
        requestId: result.requestId,
        traceId: result.traceId,
        stepUp: result.stepUp,
        forbidden: result.forbidden,
      })
    }
  }

  return {
    client: clientMeta,
    edges,
    complete: true,
    errors: collectedErrors,
    requestId,
    traceId,
    forbidden: false,
  }
}

async function collectProtocolScopes(
  request: GraphQLRequester,
  signal: AbortSignal,
): Promise<ProtocolScopeNode[]> {
  const items: ProtocolScopeNode[] = []
  const seen = new Set<string>()
  let after: string | undefined
  let loadedPages = 0
  let hasNextPage = true

  while (hasNextPage && loadedPages < MAX_SCOPE_PAGES) {
    const variables: ConsoleProtocolScopesQueryVariables = {
      first: PAGE_SIZE,
      after,
    }
    const result = await request<
      ConsoleProtocolScopesQuery,
      ConsoleProtocolScopesQueryVariables
    >(ConsoleProtocolScopesDocument, variables, 'ConsoleProtocolScopes', { signal })
    if (signal.aborted) {
      throw new DOMException('The protocol scopes walk was aborted.', 'AbortError')
    }
    const connection = result.data?.scopes ?? null
    if (!connection || result.errors.length > 0) {
      return items
    }
    for (const edge of connection.edges) {
      if (!seen.has(edge.node.id)) {
        seen.add(edge.node.id)
        items.push(edge.node)
      }
    }
    loadedPages += 1
    hasNextPage = connection.pageInfo.hasNextPage
    after = connection.pageInfo.endCursor ?? undefined
    if (hasNextPage && !after) break
  }

  return items
}

export function useClientScopes(clientId: string, loadProtocol: boolean): {
  scopes: ClientScopesSnapshot
  protocolCatalog: ProtocolScopesSnapshot
} {
  const request = useGraphQL()
  const sessionVersion = useSessionVersion()
  const { locale } = useLocale()

  const clientQuery = useQuery({
    queryKey: ['console', sessionVersion, locale, 'ClientScopesWalk', clientId],
    retry: false,
    staleTime: 0,
    queryFn: ({ signal }) => collectClientScopes(request, clientId, signal),
  })

  const protocolQuery = useQuery({
    queryKey: ['console', sessionVersion, locale, 'ProtocolScopesWalk'],
    enabled: loadProtocol,
    retry: false,
    staleTime: 0,
    queryFn: ({ signal }) => collectProtocolScopes(request, signal),
  })

  const { refetch } = clientQuery
  const reload = useCallback(async () => {
    await refetch()
  }, [refetch])

  const scopes = useMemo<ClientScopesSnapshot>(() => {
    const snapshot = clientQuery.data
    if (!snapshot) {
      return {
        status: clientQuery.isError ? 'error' : 'loading',
        client: null,
        edges: [],
        complete: false,
        errors: [],
        failure: clientQuery.isError
          ? { kind: 'network', code: 'client_scopes_request_failed' }
          : undefined,
        forbidden: false,
        refreshing: false,
        reload,
      }
    }
    return {
      status: snapshot.failure ? 'error' : 'ready',
      client: snapshot.client,
      edges: snapshot.edges,
      complete: snapshot.complete,
      errors: snapshot.errors,
      failure: snapshot.failure,
      requestId: snapshot.requestId,
      traceId: snapshot.traceId,
      stepUp: snapshot.stepUp,
      forbidden: snapshot.forbidden,
      refreshing: clientQuery.isFetching,
      reload,
    }
  }, [clientQuery.data, clientQuery.isError, clientQuery.isFetching, reload])

  const protocolCatalog = useMemo<ProtocolScopesSnapshot>(() => {
    if (!loadProtocol) return { status: 'idle', items: [] }
    if (protocolQuery.isError) return { status: 'error', items: [] }
    if (!protocolQuery.data) return { status: 'loading', items: [] }
    return { status: 'ready', items: protocolQuery.data }
  }, [loadProtocol, protocolQuery.data, protocolQuery.isError])

  return { scopes, protocolCatalog }
}
