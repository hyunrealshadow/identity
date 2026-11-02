import { useCallback, useEffect, useRef, useState } from 'react'

import {
  ConsoleUserDocument,
  type ConsoleUserQuery,
  type ConsoleUserQueryVariables,
} from '#/gql/graphql'
import type {
  GraphQLFailure,
  GraphQLIssue,
  GraphQLStepUp,
} from '#/lib/graphql/transport'
import { useGraphQL } from '#/lib/graphql/use-graphql'
import type { ProjectedUser } from '#/modules/user-management/users/lib/user-form'

export type UserDetailStatus = 'idle' | 'loading' | 'ready' | 'error'

export interface UserDetailOutcome {
  kind: 'ready' | 'notFound' | 'forbidden' | 'unauthorized' | 'error'
  user: ProjectedUser | null
  failure?: GraphQLFailure
}

export interface UserDetailState {
  status: UserDetailStatus
  user: ProjectedUser | null
  notFound: boolean
  errors: GraphQLIssue[]
  failure?: GraphQLFailure
  requestId?: string
  traceId?: string
  stepUp?: GraphQLStepUp
  partial: boolean
  forbidden: boolean
  unauthorized: boolean
  refreshing: boolean
  refresh: () => Promise<UserDetailOutcome>
  reload: () => Promise<UserDetailOutcome>
}

interface InFlight {
  key: string
  promise: Promise<UserDetailOutcome>
}

function missingUserData(
  requestId?: string,
  traceId?: string,
): GraphQLFailure {
  return {
    kind: 'invalid_response',
    code: 'missing_user',
    requestId,
    traceId,
  }
}

export function useUserDetail(
  id: string | undefined,
  enabled: boolean,
): UserDetailState {
  const request = useGraphQL()
  const [status, setStatus] = useState<UserDetailStatus>('idle')
  const [user, setUser] = useState<ProjectedUser | null>(null)
  const [notFound, setNotFound] = useState(false)
  const [errors, setErrors] = useState<GraphQLIssue[]>([])
  const [failure, setFailure] = useState<GraphQLFailure>()
  const [requestId, setRequestId] = useState<string>()
  const [traceId, setTraceId] = useState<string>()
  const [stepUp, setStepUp] = useState<GraphQLStepUp>()
  const [partial, setPartial] = useState(false)
  const [forbidden, setForbidden] = useState(false)
  const [unauthorized, setUnauthorized] = useState(false)
  const [refreshing, setRefreshing] = useState(false)
  const inFlight = useRef<InFlight | null>(null)
  const activeKey = useRef<string | undefined>(undefined)

  const load = useCallback(
    async (silent: boolean): Promise<UserDetailOutcome> => {
      if (!enabled || !id) {
        return { kind: 'error', user: null }
      }

      const key = id
      if (inFlight.current?.key === key) return inFlight.current.promise

      activeKey.current = key
      if (silent) {
        setRefreshing(true)
      } else {
        setStatus('loading')
        setUser(null)
        setNotFound(false)
        setErrors([])
        setFailure(undefined)
        setRequestId(undefined)
        setTraceId(undefined)
        setStepUp(undefined)
        setPartial(false)
        setForbidden(false)
        setUnauthorized(false)
      }

      const run = (async (): Promise<UserDetailOutcome> => {
        try {
          const variables: ConsoleUserQueryVariables = { id }
          const result = await request<ConsoleUserQuery, ConsoleUserQueryVariables>(
            ConsoleUserDocument,
            variables,
            'ConsoleUser',
          )

          if (activeKey.current !== key) {
            return { kind: 'error', user: null }
          }

          setErrors(result.errors)
          setRequestId(result.requestId)
          setTraceId(result.traceId)
          setStepUp(result.stepUp)
          setForbidden(result.forbidden)
          setUnauthorized(result.unauthorized)

          const projected = result.data?.user ?? null
          if (projected) {
            setUser(projected)
            setNotFound(false)
            setFailure(result.failure)
            setPartial(result.partial)
            setStatus('ready')
            return { kind: 'ready', user: projected, failure: result.failure }
          }

          setUser(null)
          setFailure(
            result.failure ?? missingUserData(result.requestId, result.traceId),
          )
          setPartial(false)
          setStatus('error')

          if (result.unauthorized) {
            return { kind: 'unauthorized', user: null, failure: result.failure }
          }
          if (result.forbidden) {
            return { kind: 'forbidden', user: null, failure: result.failure }
          }
          if (!result.failure && result.data) {
            setNotFound(true)
            setFailure(undefined)
            return { kind: 'notFound', user: null }
          }
          return { kind: 'error', user: null, failure: result.failure }
        } catch {
          if (activeKey.current === key) {
            const failed: GraphQLFailure = {
              kind: 'network',
              code: 'user_detail_request_failed',
            }
            setUser(null)
            setFailure(failed)
            setStatus('error')
            return { kind: 'error', user: null, failure: failed }
          }
          return { kind: 'error', user: null }
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
    [enabled, id, request],
  )

  useEffect(() => {
    if (!enabled || !id) {
      activeKey.current = undefined
      inFlight.current = null
      setStatus('idle')
      setUser(null)
      setNotFound(false)
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
    // `load` deliberately participates so an id change starts a new read.
  }, [enabled, id, load])

  const refresh = useCallback(async () => load(false), [load])
  const reload = useCallback(async () => load(true), [load])

  return {
    status,
    user,
    notFound,
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
    reload,
  }
}
