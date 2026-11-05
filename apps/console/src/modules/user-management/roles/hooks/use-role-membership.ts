import { useQuery } from '@tanstack/react-query'
import { useCallback, useMemo } from 'react'

import {
  ConsolePermissionsDocument,
  type ConsolePermissionsQuery,
  type ConsolePermissionsQueryVariables,
} from '#/generated/graphql'
import type {
  GraphQLFailure,
  GraphQLIssue,
  GraphQLStepUp,
} from '#/lib/graphql/transport'
import type { GraphQLRequester } from '#/lib/graphql/requester'
import { useGraphQL } from '#/lib/graphql/use-graphql'
import { useLocale } from '#/lib/i18n'
import type { PermissionMembershipState } from '#/modules/user-management/roles/lib/permission-selection'

export const ROLE_MEMBERSHIP_PAGE_SIZE = 25
const MAX_MEMBERSHIP_PAGES = 200

export type PermissionNode =
  ConsolePermissionsQuery['permissions']['edges'][number]['node']

export interface RoleMembershipState extends PermissionMembershipState {
  items: PermissionNode[]
  errors: GraphQLIssue[]
  failure?: GraphQLFailure
  requestId?: string
  traceId?: string
  stepUp?: GraphQLStepUp
  forbidden: boolean
  reload: () => Promise<void>
}

interface MembershipSnapshot {
  ids: Set<string>
  items: PermissionNode[]
  loadedPages: number
  hasNextPage: boolean
  errors: GraphQLIssue[]
  failure?: GraphQLFailure
  requestId?: string
  traceId?: string
  stepUp?: GraphQLStepUp
  forbidden: boolean
}

const EMPTY: RoleMembershipState = {
  status: 'idle',
  ids: new Set(),
  items: [],
  loadedPages: 0,
  hasNextPage: false,
  errors: [],
  forbidden: false,
  reload: async () => undefined,
}

/**
 * Walks every bounded page of the role's existing permission membership before
 * the caller may replace it. A failed or incomplete pass is never treated as
 * "no permissions": the snapshot carries the failure and callers stay disabled.
 */
async function collectRoleMembership(
  request: GraphQLRequester,
  roleId: string,
  includeResource: boolean,
  signal: AbortSignal,
): Promise<MembershipSnapshot> {
  const items: PermissionNode[] = []
  const seen = new Set<string>()
  const collectedErrors: GraphQLIssue[] = []
  let after: string | undefined
  let loadedPages = 0
  let hasNextPage = true
  let requestId: string | undefined
  let traceId: string | undefined

  const snapshot = (
    extra: Partial<MembershipSnapshot> = {},
  ): MembershipSnapshot => ({
    ids: seen,
    items,
    loadedPages,
    hasNextPage,
    errors: collectedErrors,
    requestId,
    traceId,
    forbidden: false,
    ...extra,
  })

  while (hasNextPage) {
    if (loadedPages >= MAX_MEMBERSHIP_PAGES) {
      return snapshot({
        hasNextPage: true,
        failure: {
          kind: 'invalid_response',
          code: 'role_membership_page_limit',
        },
      })
    }

    const variables: ConsolePermissionsQueryVariables = {
      filter: { roleId, apiOnly: true },
      orderBy: 'CODE_ASC',
      first: ROLE_MEMBERSHIP_PAGE_SIZE,
      after,
      includeResource,
    }

    const result = await request<
      ConsolePermissionsQuery,
      ConsolePermissionsQueryVariables
    >(ConsolePermissionsDocument, variables, 'ConsolePermissions', { signal })
    if (signal.aborted) {
      throw new DOMException('The role membership walk was aborted.', 'AbortError')
    }

    requestId = result.requestId
    traceId = result.traceId
    collectedErrors.push(...result.errors)

    const connection = result.data?.permissions ?? null
    if (!connection || result.errors.length > 0) {
      return snapshot({
        hasNextPage: true,
        errors: collectedErrors,
        failure:
          result.failure ?? {
            kind: 'invalid_response',
            code: connection
              ? 'role_membership_partial_failure'
              : 'missing_role_permission_connection',
            requestId: result.requestId,
            traceId: result.traceId,
          },
        requestId: result.requestId,
        traceId: result.traceId,
        stepUp: result.stepUp,
        forbidden: result.forbidden,
      })
    }

    for (const edge of connection.edges) {
      if (!seen.has(edge.node.id)) {
        seen.add(edge.node.id)
        items.push(edge.node)
      }
    }
    loadedPages += 1
    hasNextPage = connection.pageInfo.hasNextPage
    const nextAfter = connection.pageInfo.endCursor
    if (hasNextPage && !nextAfter) {
      return snapshot({
        hasNextPage: true,
        failure: {
          kind: 'invalid_response',
          code: 'missing_role_membership_cursor',
        },
      })
    }
    after = nextAfter ?? undefined

    if (loadedPages >= MAX_MEMBERSHIP_PAGES && hasNextPage) {
      return snapshot({
        hasNextPage: true,
        failure: {
          kind: 'invalid_response',
          code: 'role_membership_page_limit',
        },
      })
    }

    if (result.failure && !result.partial) {
      return snapshot({
        hasNextPage: true,
        failure: result.failure,
        requestId: result.requestId,
        traceId: result.traceId,
        stepUp: result.stepUp,
        forbidden: result.forbidden,
      })
    }
  }

  return snapshot({ hasNextPage: false })
}

/**
 * Loads every bounded page of the role's existing permission membership before
 * exposing a ready selection. A failed or incomplete pass is never treated as
 * "no permissions": callers must disable replacement.
 */
export function useRoleMembership(
  roleId: string | undefined,
  enabled: boolean,
  includeResource: boolean,
): RoleMembershipState {
  const request = useGraphQL()
  const { locale } = useLocale()
  const active = Boolean(enabled && roleId)

  const query = useQuery({
    queryKey: [
      'console',
      locale,
      'RoleMembership',
      roleId,
      includeResource,
    ],
    enabled: active,
    retry: false,
    staleTime: 0,
    queryFn: ({ signal }) =>
      collectRoleMembership(request, roleId as string, includeResource, signal),
  })

  const { refetch } = query
  const reload = useCallback(async () => {
    if (!active) return
    await refetch()
  }, [active, refetch])

  return useMemo<RoleMembershipState>(() => {
    if (!active) return { ...EMPTY, reload }
    const snapshot = query.data
    if (!snapshot) {
      return {
        ...EMPTY,
        status: query.isError ? 'error' : 'loading',
        failure: query.isError
          ? { kind: 'network', code: 'role_membership_request_failed' }
          : undefined,
        reload,
      }
    }
    return {
      status: snapshot.failure ? 'error' : 'ready',
      ids: snapshot.ids,
      items: snapshot.items,
      loadedPages: snapshot.loadedPages,
      hasNextPage: snapshot.hasNextPage,
      errors: snapshot.errors,
      failure: snapshot.failure,
      requestId: snapshot.requestId,
      traceId: snapshot.traceId,
      stepUp: snapshot.stepUp,
      forbidden: snapshot.forbidden,
      reload,
    }
  }, [active, query.data, query.isError, reload])
}
