import {
  ConsoleUserDocument,
  type ConsoleUserQuery,
  type ConsoleUserQueryVariables,
} from '#/generated/graphql'
import type {
  GraphQLFailure,
  GraphQLIssue,
  GraphQLResult,
  GraphQLStepUp,
} from '#/lib/graphql/transport'
import { useConsoleQuery } from '#/lib/graphql/use-console-query'
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

function outcomeOf(
  result: GraphQLResult<ConsoleUserQuery> | undefined,
): UserDetailOutcome {
  const user = result?.data?.user ?? null
  if (user) {
    return { kind: 'ready', user, failure: result?.failure }
  }
  if (result?.unauthorized) {
    return { kind: 'unauthorized', user: null, failure: result?.failure }
  }
  if (result?.forbidden) {
    return { kind: 'forbidden', user: null, failure: result?.failure }
  }
  if (result && !result.failure && result.data) {
    return { kind: 'notFound', user: null }
  }
  return { kind: 'error', user: null, failure: result?.failure }
}

/**
 * A single entity read. `reload` keeps the currently rendered user while the
 * next value is fetched; `refresh` reports the same outcome the page expects
 * before it decides how to recover.
 */
export function useUserDetail(
  id: string | undefined,
  enabled: boolean,
): UserDetailState {
  const query = useConsoleQuery<ConsoleUserQuery, ConsoleUserQueryVariables>(
    ConsoleUserDocument,
    id ? { id } : null,
    enabled && Boolean(id),
    'missing_user',
  )
  const user = query.data?.user ?? null
  const notFound =
    query.status === 'ready' &&
    !user &&
    !query.failure &&
    !query.forbidden &&
    !query.unauthorized

  const settle = async (): Promise<UserDetailOutcome> =>
    outcomeOf((await query.refetchResult()) ?? undefined)

  return {
    status: query.status === 'ready' && !user ? 'error' : query.status,
    user,
    notFound,
    errors: query.errors,
    failure: notFound ? undefined : query.failure,
    requestId: query.requestId,
    traceId: query.traceId,
    stepUp: query.stepUp,
    partial: query.partial,
    forbidden: query.forbidden,
    unauthorized: query.unauthorized,
    refreshing: query.refreshing,
    refresh: settle,
    reload: settle,
  }
}
