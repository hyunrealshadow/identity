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
import {
  consoleQueryKeys,
  operationNameOf,
  type ConsoleQueryKey,
} from './query-keys'

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
 * Whether the result of the previous variables may stay on screen while the
 * next ones load. `true` suits a top-level list where every variable is a
 * filter, order or cursor; a predicate restricts it to variables that still
 * describe the same owner (for example the same group's members).
 */
export type KeepPreviousData<TVariables> =
  | boolean
  | ((previous: TVariables, next: TVariables) => boolean)

export interface ConsoleQueryOptions<TVariables> {
  keepPreviousData?: KeepPreviousData<TVariables>
}

/** Keeps a placeholder only for the same owner, keyed by one variable. */
export function sameVariable<TVariables>(
  key: keyof TVariables,
): (previous: TVariables, next: TVariables) => boolean {
  return (previous, next) => previous[key] === next[key]
}

/**
 * Read boundary for console management documents, backed by TanStack Query.
 *
 * The cached value is the whole `GraphQLResult`: partial data, field errors and
 * correlation metadata stay attached to the read, and a response that carried
 * no data is surfaced as an error instead of an empty success. The query key
 * includes the locale because messages are rendered by the server, and the
 * auth provider clears the cache whenever a session is replaced. The operation
 * name comes from the document, so a key cannot drift from what it reads.
 */
export function useConsoleQuery<TData, TVariables>(
  document: string | DocumentSource<TData, TVariables>,
  variables: TVariables | null,
  enabled: boolean,
  missingCode: string,
  options: ConsoleQueryOptions<TVariables> = {},
): ConsoleQueryState<TData> {
  const request = useGraphQL()
  const { locale } = useLocale()
  const sessionVersion = useSessionVersion()
  const active = enabled && variables !== null
  const operationName = operationNameOf(document)

  const keepPrevious = options.keepPreviousData ?? false

  const query = useQuery<
    GraphQLResult<TData>,
    Error,
    GraphQLResult<TData>,
    ConsoleQueryKey<TVariables>
  >({
    queryKey: consoleQueryKeys.read(sessionVersion, locale, document, variables),
    queryFn: async ({ signal }) => {
      if (variables === null) {
        throw new Error(`Console query ${operationName} has no variables`)
      }
      return request<TData, TVariables>(document, variables, operationName, {
        signal,
      })
    },
    enabled: active,
    // Changing a page, filter or order keeps the previous rows mounted, so
    // the table refreshes its data rows instead of replacing the whole list.
    // A placeholder never crosses a session, locale or owner boundary.
    placeholderData: (previous, previousQuery) => {
      if (
        !keepPrevious ||
        !previous?.data ||
        !previousQuery ||
        variables === null
      ) {
        return undefined
      }
      const [, previousSession, previousLocale, previousOperation, previousVariables] =
        previousQuery.queryKey
      if (
        previousSession !== sessionVersion ||
        previousLocale !== locale ||
        previousOperation !== operationName ||
        previousVariables === null
      ) {
        return undefined
      }
      if (
        typeof keepPrevious === 'function' &&
        !keepPrevious(previousVariables, variables)
      ) {
        return undefined
      }
      return previous
    },
  })

  const { refetch } = query
  const refetchResult = useCallback(async () => {
    if (!active) return null
    // Join a fetch that is already running (for example the refetch a
    // mutation's invalidation just started) instead of cancelling it and
    // sending the same read again. That fetch began after the write, so its
    // result is as fresh as a new one.
    const next = await refetch({ cancelRefetch: false })
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
      // Also true while a kept placeholder waits for the next variables.
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
