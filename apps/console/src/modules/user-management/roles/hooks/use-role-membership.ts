import { useCallback, useEffect, useRef, useState } from 'react'

import {
  ConsolePermissionsDocument,
  type ConsolePermissionsQuery,
  type ConsolePermissionsQueryVariables,
} from '#/gql/graphql'
import type {
  GraphQLFailure,
  GraphQLIssue,
  GraphQLStepUp,
} from '#/lib/graphql/transport'
import { useGraphQL } from '#/lib/graphql/use-graphql'
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
  const [state, setState] = useState<RoleMembershipState>(EMPTY)
  const activeKey = useRef<string | undefined>(undefined)
  const inFlight = useRef<Promise<void> | null>(null)

  const reload = useCallback(async () => {
    if (!roleId || !enabled) {
      setState(EMPTY)
      return
    }
    const key = `${roleId}:${includeResource}`
    activeKey.current = key
    setState({
      ...EMPTY,
      status: 'loading',
    })

    const run = (async () => {
      const items: PermissionNode[] = []
      const seen = new Set<string>()
      let after: string | undefined
      let loadedPages = 0
      let hasNextPage = true
      let lastRequestId: string | undefined
      let lastTraceId: string | undefined
      const collectedErrors: GraphQLIssue[] = []

      while (hasNextPage) {
        if (loadedPages >= MAX_MEMBERSHIP_PAGES) {
          setState({
            ...EMPTY,
            status: 'error',
            items,
            ids: seen,
            loadedPages,
            hasNextPage: true,
            errors: collectedErrors,
            failure: {
              kind: 'invalid_response',
              code: 'role_membership_page_limit',
            },
          })
          return
        }

        const variables: ConsolePermissionsQueryVariables = {
          filter: { roleId, apiOnly: true },
          orderBy: 'CODE_ASC',
          first: ROLE_MEMBERSHIP_PAGE_SIZE,
          after,
          includeResource,
        }

        let result
        try {
          result = await request<ConsolePermissionsQuery, ConsolePermissionsQueryVariables>(
            ConsolePermissionsDocument,
            variables,
            'ConsolePermissions',
          )
        } catch {
          if (activeKey.current === key) {
            setState({
              ...EMPTY,
              status: 'error',
              items,
              ids: seen,
              loadedPages,
              hasNextPage: true,
              errors: collectedErrors,
              failure: {
                kind: 'network',
                code: 'role_membership_request_failed',
              },
            })
          }
          return
        }

        if (activeKey.current !== key) return
        lastRequestId = result.requestId
        lastTraceId = result.traceId
        collectedErrors.push(...result.errors)
        const connection = result.data?.permissions ?? null
        if (!connection || result.errors.length > 0) {
          setState({
            ...EMPTY,
            status: 'error',
            items,
            ids: seen,
            loadedPages,
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
          return
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
          setState({
            ...EMPTY,
            status: 'error',
            items,
            ids: seen,
            loadedPages,
            hasNextPage: true,
            errors: collectedErrors,
            failure: {
              kind: 'invalid_response',
              code: 'missing_role_membership_cursor',
            },
            requestId: result.requestId,
            traceId: result.traceId,
          })
          return
        }
        after = nextAfter ?? undefined

        if (loadedPages >= MAX_MEMBERSHIP_PAGES && hasNextPage) {
          setState({
            ...EMPTY,
            status: 'error',
            items,
            ids: seen,
            loadedPages,
            hasNextPage: true,
            errors: collectedErrors,
            failure: {
              kind: 'invalid_response',
              code: 'role_membership_page_limit',
            },
            requestId: result.requestId,
            traceId: result.traceId,
          })
          return
        }

        if (result.failure && !result.partial) {
          setState({
            ...EMPTY,
            status: 'error',
            items,
            ids: seen,
            loadedPages,
            hasNextPage: true,
            errors: collectedErrors,
            failure: result.failure,
            requestId: result.requestId,
            traceId: result.traceId,
            stepUp: result.stepUp,
            forbidden: result.forbidden,
          })
          return
        }
      }

      setState({
        status: 'ready',
        ids: seen,
        items,
        loadedPages,
        hasNextPage: false,
        errors: collectedErrors,
        requestId: lastRequestId,
        traceId: lastTraceId,
        forbidden: false,
        reload,
      })
    })()

    inFlight.current = run
    await run
    if (inFlight.current === run) inFlight.current = null
  }, [enabled, includeResource, request, roleId])

  useEffect(() => {
    if (!enabled || !roleId) {
      activeKey.current = undefined
      setState(EMPTY)
      return
    }
    void reload()
    return () => {
      activeKey.current = undefined
    }
  }, [enabled, reload, roleId])

  return { ...state, reload }
}
