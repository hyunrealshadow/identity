import { useCallback, useEffect, useRef, useState } from 'react'

import {
  ConsoleUsersDocument,
  type ConsoleUsersQuery,
  type ConsoleUsersQueryVariables,
} from '#/gql/graphql'
import type {
  GraphQLFailure,
  GraphQLIssue,
  GraphQLStepUp,
} from '#/lib/graphql/transport'
import { useGraphQL } from '#/lib/graphql/use-graphql'

export type UserConnection = ConsoleUsersQuery['users']
export type UserSummary = UserConnection['edges'][number]['node']
export type UsersPageInfo = UserConnection['pageInfo']

export type UsersStatus = 'idle' | 'loading' | 'ready' | 'error'

export interface UsersState {
  status: UsersStatus
  data: UserConnection | null
  errors: GraphQLIssue[]
  failure?: GraphQLFailure
  requestId?: string
  traceId?: string
  stepUp?: GraphQLStepUp
  partial: boolean
  forbidden: boolean
  refreshing: boolean
  refresh: () => Promise<void>
}

interface InFlight {
  key: string
  promise: Promise<void>
}

function missingUsersData(
  requestId?: string,
  traceId?: string,
): GraphQLFailure {
  return {
    kind: 'invalid_response',
    code: 'missing_user_connection',
    requestId,
    traceId,
  }
}

export function useUsers(
  variables: ConsoleUsersQueryVariables | null,
  enabled: boolean,
): UsersState {
  const request = useGraphQL()
  const [status, setStatus] = useState<UsersStatus>('idle')
  const [data, setData] = useState<UserConnection | null>(null)
  const [errors, setErrors] = useState<GraphQLIssue[]>([])
  const [failure, setFailure] = useState<GraphQLFailure>()
  const [requestId, setRequestId] = useState<string>()
  const [traceId, setTraceId] = useState<string>()
  const [stepUp, setStepUp] = useState<GraphQLStepUp>()
  const [partial, setPartial] = useState(false)
  const [forbidden, setForbidden] = useState(false)
  const [refreshing, setRefreshing] = useState(false)
  const inFlight = useRef<InFlight | null>(null)
  const activeKey = useRef<string | undefined>(undefined)
  const requestKey = variables ? JSON.stringify(variables) : undefined

  const load = useCallback(
    async (silent: boolean) => {
      if (!enabled || !variables || !requestKey) return
      const key = requestKey
      if (inFlight.current?.key === key) return inFlight.current.promise

      activeKey.current = key
      const run = (async () => {
        if (silent) {
          setRefreshing(true)
        } else {
          setRefreshing(false)
          setStatus('loading')
          setData(null)
          setErrors([])
          setFailure(undefined)
          setRequestId(undefined)
          setTraceId(undefined)
          setStepUp(undefined)
          setPartial(false)
          setForbidden(false)
        }

        try {
          const result = await request<
            ConsoleUsersQuery,
            ConsoleUsersQueryVariables
          >(ConsoleUsersDocument, variables, 'ConsoleUsers')

          if (activeKey.current !== key) return

          setErrors(result.errors)
          setRequestId(result.requestId)
          setTraceId(result.traceId)
          setStepUp(result.stepUp)
          setForbidden(result.forbidden)

          const connection = result.data?.users ?? null
          if (connection) {
            setData(connection)
            setFailure(result.failure)
            setPartial(result.partial)
            setStatus('ready')
          } else {
            setData(null)
            setFailure(
              result.failure ??
                missingUsersData(result.requestId, result.traceId),
            )
            setPartial(false)
            setStatus('error')
          }
        } catch {
          if (activeKey.current === key) {
            setData(null)
            setFailure({ kind: 'network', code: 'user_list_request_failed' })
            setStatus('error')
          }
        } finally {
          if (activeKey.current === key) setRefreshing(false)
        }
      })()

      const entry: InFlight = { key, promise: run }
      inFlight.current = entry
      void run.finally(() => {
        if (inFlight.current === entry) inFlight.current = null
      })
      return run
    },
    [enabled, request, requestKey, variables],
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
      setRefreshing(false)
      return
    }
    void load(false)
  }, [enabled, load, variables])

  const refresh = useCallback(async () => {
    await load(true)
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
    refreshing,
    refresh,
  }
}
