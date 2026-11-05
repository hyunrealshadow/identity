import { useQuery } from '@tanstack/react-query'
import { useCallback, useMemo } from 'react'

import { useSessionVersion } from '#/lib/auth/session-version'
import { useLocale } from '#/lib/i18n'
import {
  type DocumentSource,
  type GraphQLFailure,
  type GraphQLIssue,
  type GraphQLResult,
  type GraphQLStepUp,
} from '#/lib/graphql/transport'
import { useGraphQL } from '#/lib/graphql/use-graphql'

export type ConsoleQueryStatus = 'idle' | 'loading' | 'ready' | 'error'

export interface ConsoleQueryState<TData> {
  status: ConsoleQueryStatus
  data: TData | null
  errors: GraphQLIssue[]
  failure?: GraphQLFailure
  requestId?: string
  traceId?: string
  stepUp?: GraphQLStepUp
  partial: boolean
  forbidden: boolean
  unauthorized: boolean
  refreshing: boolean
  refresh: () => Promise<TData | null>
  /** Full result, including failure and correlation, for callers that branch on more than data. */
  refetchResult: () => Promise<GraphQLResult<TData> | null>
}

/**
 * Read boundary for console management documents, backed by TanStack Query.
 *
 * The cached value is the whole `GraphQLResult`: partial data, field errors and
 * correlation metadata stay attached to the read, and a response that carried
 * no data is surfaced as an error instead of an empty success. The query key
 * includes the locale because messages are rendered by the server, and the
 * auth provider clears the cache whenever a session is replaced.
 */
export function useConsoleQuery<TData, TVariables>(
  document: string | DocumentSource<TData, TVariables>,
  variables: TVariables | null,
  operationName: string,
  enabled: boolean,
  missingCode: string,
): ConsoleQueryState<TData> {
  const request = useGraphQL()
  const { locale } = useLocale()
  const sessionVersion = useSessionVersion()
  const active = enabled && variables !== null

  const query = useQuery({
    queryKey: [
      'console',
      sessionVersion,
      locale,
      operationName,
      variables,
    ],
    queryFn: async ({ signal }) => {
      if (variables === null) {
        throw new Error(`Console query ${operationName} has no variables`)
      }
      return request<TData, TVariables>(document, variables, operationName, {
        signal,
      })
    },
    enabled: active,
    retry: false,
    staleTime: 0,
  })

  const { refetch } = query
  const refetchResult = useCallback(async () => {
    if (!active) return null
    const next = await refetch()
    return next.data ?? null
  }, [active, refetch])

  const refresh = useCallback(async () => {
    const next = await refetchResult()
    return next?.data ?? null
  }, [refetchResult])

  const result = query.data

  return useMemo<ConsoleQueryState<TData>>(() => {
    if (!active) {
      return {
        status: 'idle',
        data: null,
        errors: [],
        partial: false,
        forbidden: false,
        unauthorized: false,
        refreshing: false,
        refresh,
        refetchResult,
      }
    }

    const data = result?.data ?? null
    const failure = result
      ? result.failure ??
        (data === null
          ? {
              kind: 'invalid_response' as const,
              code: missingCode,
              requestId: result.requestId,
              traceId: result.traceId,
            }
          : undefined)
      : query.isError
        ? { kind: 'network' as const, code: `${missingCode}_network` }
        : undefined

    return {
      status: query.isPending ? 'loading' : data !== null ? 'ready' : 'error',
      data,
      errors: result?.errors ?? [],
      failure,
      requestId: result?.requestId,
      traceId: result?.traceId,
      stepUp: result?.stepUp,
      partial: result?.partial ?? false,
      forbidden: result?.forbidden ?? false,
      unauthorized: result?.unauthorized ?? false,
      refreshing: query.isFetching && !query.isPending,
      refresh,
      refetchResult,
    }
  }, [
    active,
    missingCode,
    query.isError,
    query.isFetching,
    query.isPending,
    refresh,
    refetchResult,
    result,
  ])
}
