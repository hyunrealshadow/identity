import { useQuery } from '@tanstack/react-query'
import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  type ReactNode,
} from 'react'

import { useAuth } from '#/lib/auth/context'
import { getAuthSession, type AuthSession } from '#/lib/auth/session'
import {
  ConsoleBootstrapDocument,
  type ConsoleBootstrapQuery,
  type ConsoleBootstrapQueryVariables,
} from '#/generated/graphql'
import {
  type GraphQLFailure,
  type GraphQLIssue,
  type GraphQLResult,
  type GraphQLStepUp,
} from '#/lib/graphql/transport'
import { RequestableAccessContext } from '#/lib/graphql/access-context'
import { consoleQueryKeys } from '#/lib/graphql/query-keys'
import { useGraphQL } from '#/lib/graphql/use-graphql'
import { useLocale } from '#/lib/i18n'

export type EffectivePermissions = ConsoleBootstrapQuery['effectivePermissions']
export type InstanceInfo = ConsoleBootstrapQuery['instanceInfo']

export interface WorkspaceData {
  effectivePermissions: EffectivePermissions | null
  instanceInfo: InstanceInfo | null
}

export type WorkspaceStatus = 'idle' | 'loading' | 'ready' | 'reauth' | 'error'

interface WorkspaceContextValue {
  status: WorkspaceStatus
  data?: WorkspaceData
  errors: GraphQLIssue[]
  failure?: GraphQLFailure
  requestId?: string
  traceId?: string
  stepUp?: GraphQLStepUp
  partial: boolean
  forbidden: boolean
  refresh: () => Promise<void>
}

interface BootstrapSnapshot {
  result: GraphQLResult<ConsoleBootstrapQuery>
  /** The validated session this capability snapshot belongs to. */
  session: AuthSession | null
}

const WorkspaceContext = createContext<WorkspaceContextValue | null>(null)

function missingOverviewData(
  requestId?: string,
  traceId?: string,
): GraphQLFailure {
  return {
    kind: 'invalid_response',
    code: 'missing_overview_data',
    requestId,
    traceId,
  }
}

export function WorkspaceProvider({ children }: { children: ReactNode }) {
  const {
    status: authStatus,
    sessionVersion,
    requireReauthentication,
  } = useAuth()
  const request = useGraphQL()
  const { locale } = useLocale()

  const query = useQuery({
    queryKey: consoleQueryKeys.read(
      sessionVersion,
      locale,
      ConsoleBootstrapDocument,
      {},
    ),
    enabled: authStatus === 'authenticated',
    queryFn: async ({ signal }): Promise<BootstrapSnapshot> => {
      const session = getAuthSession()
      const result = await request<
        ConsoleBootstrapQuery,
        ConsoleBootstrapQueryVariables
      >(ConsoleBootstrapDocument, {}, 'ConsoleBootstrap', { signal })
      return { result, session }
    },
  })

  const snapshot = query.data
  const result = snapshot?.result
  // Bootstrap capabilities belong to one validated session. A late result of
  // its predecessor is never applied to the successor's workspace.
  const currentSession = getAuthSession()
  const current =
    authStatus === 'authenticated' &&
    snapshot !== undefined &&
    snapshot.session === currentSession

  useEffect(() => {
    if (!current || !result) return
    if (!result.stepUp && !result.unauthorized) return
    // Keep the bootstrap gate loading until the central coordinator navigates,
    // so pages never flash a denial for access authentication can recover.
    void requireReauthentication(result.stepUp, {
      requestId: result.requestId,
      traceId: result.traceId,
      reason: result.stepUp ? 'step_up' : 'unauthorized',
    })
  }, [current, result, requireReauthentication])

  const { refetch } = query
  const refresh = useCallback(async () => {
    await refetch()
  }, [refetch])

  const effectivePermissions = current
    ? (result?.data?.effectivePermissions ?? null)
    : null
  const instanceInfo = current ? (result?.data?.instanceInfo ?? null) : null
  const hasAnyRoot = Boolean(effectivePermissions || instanceInfo)
  const challenged = Boolean(result?.stepUp || result?.unauthorized)

  const status: WorkspaceStatus =
    authStatus !== 'authenticated'
      ? 'idle'
      : !current || query.isPending
        ? 'loading'
        : challenged
          ? 'reauth'
          : hasAnyRoot
            ? 'ready'
            : 'error'

  const value = useMemo<WorkspaceContextValue>(
    () => ({
      status,
      data:
        current && (hasAnyRoot || challenged)
          ? { effectivePermissions, instanceInfo }
          : undefined,
      errors: current ? (result?.errors ?? []) : [],
      failure:
        current && status === 'error'
          ? (result?.failure ??
            missingOverviewData(result?.requestId, result?.traceId))
          : undefined,
      requestId: current ? result?.requestId : undefined,
      traceId: current ? result?.traceId : undefined,
      stepUp: current ? result?.stepUp : undefined,
      partial:
        current && status === 'ready'
          ? (result?.partial ?? false) || !effectivePermissions || !instanceInfo
          : false,
      forbidden: current ? (result?.forbidden ?? false) : false,
      refresh,
    }),
    [
      challenged,
      current,
      effectivePermissions,
      hasAnyRoot,
      instanceInfo,
      refresh,
      result,
      status,
    ],
  )

  const requestableAccess = useMemo(
    () =>
      current && effectivePermissions
        ? {
            session: snapshot.session as AuthSession,
            scopes: effectivePermissions.requestableScopes,
          }
        : null,
    [current, effectivePermissions, snapshot],
  )

  return (
    <WorkspaceContext.Provider value={value}>
      <RequestableAccessContext.Provider value={requestableAccess}>
        {children}
      </RequestableAccessContext.Provider>
    </WorkspaceContext.Provider>
  )
}

export function useWorkspace(): WorkspaceContextValue {
  const value = useContext(WorkspaceContext)
  if (!value)
    throw new Error('useWorkspace must be used inside WorkspaceProvider')
  return value
}
