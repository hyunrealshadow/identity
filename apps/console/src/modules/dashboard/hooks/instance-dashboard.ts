import { useCallback, useEffect, useMemo, useRef, useState } from 'react'

import {
  InstanceDashboardDocument,
  type InstanceDashboardQuery,
  type InstanceDashboardQueryVariables,
} from '#/gql/graphql'
import {
  type GraphQLFailure,
  type GraphQLIssue,
} from '#/lib/graphql/transport'
import { useLocale } from '#/lib/i18n'
import { useGraphQL } from '#/lib/graphql/use-graphql'
import type { EffectivePermissions } from '#/lib/workspace'
import { dashboardScope, type DashboardScope } from '#/modules/dashboard/lib/dashboard-scope'

export type InstanceOverview = NonNullable<InstanceDashboardQuery['instanceOverview']>
export type InstanceDashboardUsers = NonNullable<InstanceOverview['users']>
export type InstanceDashboardApplications = NonNullable<InstanceOverview['applications']>
export type InstanceDashboardSessions = NonNullable<InstanceOverview['sessions']>
export type InstanceDashboardResources = NonNullable<InstanceOverview['resources']>
export type RegistrationBucket = InstanceDashboardUsers['registrations'][number]

export type DashboardStatus = 'idle' | 'loading' | 'ready' | 'error'

export interface InstanceDashboardState {
  status: DashboardStatus
  data: InstanceOverview | null
  scope: DashboardScope
  errors: GraphQLIssue[]
  failure?: GraphQLFailure
  requestId?: string
  traceId?: string
  partial: boolean
  forbidden: boolean
  refreshing: boolean
  refresh: () => Promise<void>
}

interface InFlight {
  key: string
  promise: Promise<void>
}

function missingDashboardData(
  requestId?: string,
  traceId?: string,
): GraphQLFailure {
  return {
    kind: 'invalid_response',
    code: 'missing_instance_overview',
    requestId,
    traceId,
  }
}

/**
 * Loads the single instance dashboard aggregate. The operation is skipped
 * entirely when bootstrap reports no effective management read scope, and each
 * aggregate is selected only when its matching scope is effective.
 */
export function useInstanceDashboard(
  permissions: EffectivePermissions | null | undefined,
): InstanceDashboardState {
  const request = useGraphQL()
  const { timeZone } = useLocale()
  const scope = useMemo(() => dashboardScope(permissions), [permissions])
  const [status, setStatus] = useState<DashboardStatus>('idle')
  const [data, setData] = useState<InstanceOverview | null>(null)
  const [errors, setErrors] = useState<GraphQLIssue[]>([])
  const [failure, setFailure] = useState<GraphQLFailure>()
  const [requestId, setRequestId] = useState<string>()
  const [traceId, setTraceId] = useState<string>()
  const [partial, setPartial] = useState(false)
  const [forbidden, setForbidden] = useState(false)
  const [refreshing, setRefreshing] = useState(false)
  const inFlight = useRef<InFlight | null>(null)
  const loaded = useRef(false)
  const activeKey = useRef<string | undefined>(undefined)
  const scopeKey = `${timeZone}:${Number(scope.users)}${Number(scope.applications)}${Number(scope.sessions)}${Number(scope.resources)}`
  const selection = useRef(scopeKey)

  const load = useCallback(async () => {
    if (!scope.hasAny) return
    if (inFlight.current?.key === scopeKey) return inFlight.current.promise

    const key = scopeKey
    const selectionChanged = selection.current !== key
    selection.current = key
    activeKey.current = key
    const run = (async () => {
      try {
        if (loaded.current && !selectionChanged) {
          setRefreshing(true)
        } else {
          setData(null)
          setErrors([])
          setRequestId(undefined)
          setTraceId(undefined)
          setPartial(false)
          setStatus('loading')
        }
        setFailure(undefined)
        setForbidden(false)

        const variables: InstanceDashboardQueryVariables = {
          timeZone,
          includeUsers: scope.users,
          includeApplications: scope.applications,
          includeSessions: scope.sessions,
          includeResources: scope.resources,
        }
        const result = await request<
          InstanceDashboardQuery,
          InstanceDashboardQueryVariables
        >(InstanceDashboardDocument, variables, 'InstanceDashboard')

        // A newer selection replaced this request while it was in flight.
        if (activeKey.current !== key) return

        setErrors(result.errors)
        setRequestId(result.requestId)
        setTraceId(result.traceId)
        setForbidden(result.forbidden)

        const overview = result.data?.instanceOverview ?? null
        if (overview) {
          setData(overview)
          setFailure(result.failure)
          setPartial(result.partial)
          setStatus('ready')
        } else {
          setData(null)
          setFailure(
            result.failure ?? missingDashboardData(result.requestId, result.traceId),
          )
          setPartial(false)
          setStatus('error')
        }

        loaded.current = true
      } catch {
        if (activeKey.current === key) {
          setData(null)
          setErrors([])
          setRequestId(undefined)
          setTraceId(undefined)
          setFailure({ kind: 'network', code: 'dashboard_request_failed' })
          setPartial(false)
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
  }, [request, scope, scopeKey, timeZone])

  useEffect(() => {
    if (!scope.hasAny) {
      loaded.current = false
      inFlight.current = null
      activeKey.current = undefined
      setStatus('idle')
      setData(null)
      setErrors([])
      setFailure(undefined)
      setRequestId(undefined)
      setTraceId(undefined)
      setPartial(false)
      setForbidden(false)
      setRefreshing(false)
      return
    }
    void load()
  }, [load, scope.hasAny])

  const refresh = useCallback(async () => {
    await load()
  }, [load])

  return {
    status,
    data,
    scope,
    errors,
    failure,
    requestId,
    traceId,
    partial,
    forbidden,
    refreshing,
    refresh,
  }
}
