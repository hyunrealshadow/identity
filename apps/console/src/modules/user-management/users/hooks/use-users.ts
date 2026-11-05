import {
  ConsoleUsersDocument,
  type ConsoleUsersQuery,
  type ConsoleUsersQueryVariables,
} from '#/generated/graphql'
import type {
  GraphQLFailure,
  GraphQLIssue,
  GraphQLStepUp,
} from '#/lib/graphql/transport'
import { useConsoleQuery } from '#/lib/graphql/use-console-query'

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
  const query = useConsoleQuery<ConsoleUsersQuery, ConsoleUsersQueryVariables>(
    ConsoleUsersDocument,
    variables,
    'ConsoleUsers',
    enabled,
    'missing_user_connection',
  )
  const connection = query.data?.users ?? null
  // The generated connection is nullable; a null connection is an invalid
  // response for this operation, not an empty page.
  const missing = query.status === 'ready' && connection === null

  return {
    status: missing ? 'error' : query.status,
    data: connection,
    errors: query.errors,
    failure:
      missing && !query.failure
        ? missingUsersData(query.requestId, query.traceId)
        : query.failure,
    requestId: query.requestId,
    traceId: query.traceId,
    stepUp: query.stepUp,
    partial: query.partial,
    forbidden: query.forbidden,
    refreshing: query.refreshing,
    refresh: async () => {
      await query.refresh()
    },
  }
}
