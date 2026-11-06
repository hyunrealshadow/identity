import { useMemo } from 'react'

import {
  InstanceDashboardDocument,
  type InstanceDashboardQuery,
  type InstanceDashboardQueryVariables,
} from '#/generated/graphql'
import {
  type GraphQLFailure,
  type GraphQLIssue,
} from '#/lib/graphql/transport'
import { useConsoleQuery } from '#/lib/graphql/use-console-query'
import { useLocale } from '#/lib/i18n'
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
  const { timeZone } = useLocale()
  const scope = useMemo(() => dashboardScope(permissions), [permissions])
  const variables = useMemo<InstanceDashboardQueryVariables>(
    () => ({
      timeZone,
      includeUsers: scope.users,
      includeApplications: scope.applications,
      includeSessions: scope.sessions,
      includeResources: scope.resources,
    }),
    [scope, timeZone],
  )

  const query = useConsoleQuery<
    InstanceDashboardQuery,
    InstanceDashboardQueryVariables
  >(
    InstanceDashboardDocument,
    variables,
    scope.hasAny,
    'missing_instance_overview',
  )
  const overview = query.data?.instanceOverview ?? null
  const missing = query.status === 'ready' && overview === null

  return {
    status: missing ? 'error' : query.status,
    data: overview,
    scope,
    errors: query.errors,
    failure:
      missing && !query.failure
        ? missingDashboardData(query.requestId, query.traceId)
        : query.failure,
    requestId: query.requestId,
    traceId: query.traceId,
    partial: query.partial,
    forbidden: query.forbidden,
    refreshing: query.refreshing,
    refresh: async () => {
      await query.refresh()
    },
  }
}
