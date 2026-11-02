import { useCallback, useEffect, useRef, useState } from 'react'

import type {
  DocumentSource,
  GraphQLFailure,
  GraphQLIssue,
  GraphQLStepUp,
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
}

interface LoadState {
  key: string
  promise: Promise<unknown>
}

/**
 * Small read boundary for console management documents. It never retries and
 * keeps partial GraphQL data usable while preserving correlation metadata.
 */
export function useConsoleQuery<TData, TVariables>(
  document: string | DocumentSource<TData, TVariables>,
  variables: TVariables | null,
  operationName: string,
  enabled: boolean,
  missingCode: string,
): ConsoleQueryState<TData> {
  const request = useGraphQL()
  const [status, setStatus] = useState<ConsoleQueryStatus>('idle')
  const [data, setData] = useState<TData | null>(null)
  const [errors, setErrors] = useState<GraphQLIssue[]>([])
  const [failure, setFailure] = useState<GraphQLFailure>()
  const [requestId, setRequestId] = useState<string>()
  const [traceId, setTraceId] = useState<string>()
  const [stepUp, setStepUp] = useState<GraphQLStepUp>()
  const [partial, setPartial] = useState(false)
  const [forbidden, setForbidden] = useState(false)
  const [unauthorized, setUnauthorized] = useState(false)
  const [refreshing, setRefreshing] = useState(false)
  const inFlight = useRef<LoadState | null>(null)
  const activeKey = useRef<string | undefined>(undefined)
  const requestKey =
    enabled && variables ? JSON.stringify(variables) : undefined
  const variablesRef = useRef(variables)
  variablesRef.current = variables

  const load = useCallback(
    async (silent: boolean) => {
      if (!enabled || !requestKey) return null
      const key = requestKey
      if (inFlight.current?.key === key) {
        return inFlight.current.promise as Promise<TData | null>
      }

      activeKey.current = key
      if (silent) {
        setRefreshing(true)
      } else {
        setStatus('loading')
        setData(null)
        setErrors([])
        setFailure(undefined)
        setRequestId(undefined)
        setTraceId(undefined)
        setStepUp(undefined)
        setPartial(false)
        setForbidden(false)
        setUnauthorized(false)
      }

      const run = (async (): Promise<TData | null> => {
        try {
          const currentVariables = variablesRef.current
          if (!currentVariables) return null
          const result = await request<TData, TVariables>(
            document,
            currentVariables,
            operationName,
          )
          if (activeKey.current !== key) return null

          setErrors(result.errors)
          setRequestId(result.requestId)
          setTraceId(result.traceId)
          setStepUp(result.stepUp)
          setForbidden(result.forbidden)
          setUnauthorized(result.unauthorized)
          setPartial(result.partial)

          if (result.data !== null) {
            setData(result.data)
            setFailure(result.failure)
            setStatus('ready')
            return result.data
          }

          setData(null)
          setFailure(
            result.failure ?? {
              kind: 'invalid_response',
              code: missingCode,
              requestId: result.requestId,
              traceId: result.traceId,
            },
          )
          setStatus('error')
          return null
        } catch {
          if (activeKey.current === key) {
            setData(null)
            setFailure({ kind: 'network', code: `${missingCode}_network` })
            setStatus('error')
          }
          return null
        } finally {
          if (activeKey.current === key) setRefreshing(false)
        }
      })()

      const entry: LoadState = { key, promise: run }
      inFlight.current = entry
      void run.finally(() => {
        if (inFlight.current === entry) inFlight.current = null
      })
      return run
    },
    [document, enabled, missingCode, operationName, request, requestKey],
  )

  useEffect(() => {
    if (!enabled || !variables) {
      activeKey.current = undefined
      inFlight.current = null
      setStatus('idle')
      setData(null)
      setErrors([])
      setFailure(undefined)
      setRequestId(undefined)
      setTraceId(undefined)
      setStepUp(undefined)
      setPartial(false)
      setForbidden(false)
      setUnauthorized(false)
      setRefreshing(false)
      return
    }
    void load(false)
    // requestKey is the stable serialization of the current variables.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [enabled, load, requestKey])

  const refresh = useCallback(async () => {
    return load(true)
  }, [load])

  return {
    status,
    data,
    errors,
    failure,
    requestId,
    traceId,
    stepUp,
    partial,
    forbidden,
    unauthorized,
    refreshing,
    refresh,
  }
}
