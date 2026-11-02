import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useRef,
  useState,
  type ReactNode,
} from 'react'

import { useAuth } from '#/lib/auth/context'
import { getAuthSession, type AuthSession } from '#/lib/auth/session'
import {
  ConsoleBootstrapDocument,
  type ConsoleBootstrapQuery,
  type ConsoleBootstrapQueryVariables,
} from '#/gql/graphql'
import {
  type GraphQLFailure,
  type GraphQLIssue,
  type GraphQLStepUp,
} from '#/lib/graphql/transport'
import { RequestableAccessContext } from '#/lib/graphql/access-context'
import { useGraphQL } from '#/lib/graphql/use-graphql'

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
  const [status, setStatus] = useState<WorkspaceStatus>('idle')
  const [data, setData] = useState<WorkspaceData>()
  const [errors, setErrors] = useState<GraphQLIssue[]>([])
  const [failure, setFailure] = useState<GraphQLFailure>()
  const [requestId, setRequestId] = useState<string>()
  const [traceId, setTraceId] = useState<string>()
  const [stepUp, setStepUp] = useState<GraphQLStepUp>()
  const [partial, setPartial] = useState(false)
  const [forbidden, setForbidden] = useState(false)
  const [loadedSession, setLoadedSession] = useState<AuthSession | null>(null)
  const currentSession = getAuthSession()
  const inFlight = useRef<{
    session: AuthSession | null
    promise: Promise<void>
  } | null>(null)

  const load = useCallback(async () => {
    const session = getAuthSession()
    if (inFlight.current?.session === session) return inFlight.current.promise
    const run = (async () => {
      setStatus('loading')
      setFailure(undefined)
      const result = await request<
        ConsoleBootstrapQuery,
        ConsoleBootstrapQueryVariables
      >(ConsoleBootstrapDocument, {}, 'ConsoleBootstrap')
      // Bootstrap capabilities belong to one validated session. Discard a late
      // result rather than applying old freshness or permissions to its successor.
      if (getAuthSession() !== session) return
      setLoadedSession(session)
      setErrors(result.errors)
      setRequestId(result.requestId)
      setTraceId(result.traceId)
      setStepUp(result.stepUp)
      setForbidden(result.forbidden)

      const effectivePermissions = result.data?.effectivePermissions ?? null
      const instanceInfo = result.data?.instanceInfo ?? null
      const hasAnyRoot = Boolean(effectivePermissions || instanceInfo)
      // Bootstrap describes current capabilities. Missing write freshness is
      // handled by the selected operation's access contract, not by re-login.
      if (result.stepUp || result.unauthorized) {
        // Keep the bootstrap gate in a loading state until the central
        // coordinator navigates, so individual pages never flash a denial for
        // access that authentication is about to recover.
        setData({ effectivePermissions, instanceInfo })
        setFailure(undefined)
        setPartial(false)
        setStatus('reauth')
        void requireReauthentication(result.stepUp, {
          requestId: result.requestId,
          traceId: result.traceId,
          reason: result.stepUp
            ? 'step_up'
            : result.unauthorized
              ? 'unauthorized'
              : 'policy',
        })
        return
      }

      if (!hasAnyRoot) {
        setData(undefined)
        setFailure(
          result.failure ??
            missingOverviewData(result.requestId, result.traceId),
        )
        setPartial(false)
        setStatus('error')
        return
      }

      setData({ effectivePermissions, instanceInfo })
      setFailure(result.failure)
      // Each bootstrap root is loaded independently. Keep the successful root,
      // but make the missing one visible instead of replacing the whole page.
      setPartial(result.partial || !effectivePermissions || !instanceInfo)
      setStatus('ready')
    })()
    const entry = { session, promise: run }
    inFlight.current = entry
    void run.finally(() => {
      if (inFlight.current === entry) inFlight.current = null
    })
    return run
  }, [request, requireReauthentication])

  useEffect(() => {
    if (authStatus !== 'authenticated') {
      setStatus('idle')
      setData(undefined)
      setLoadedSession(null)
      setErrors([])
      setFailure(undefined)
      setPartial(false)
      inFlight.current = null
      return
    }
    void load()
  }, [authStatus, sessionVersion, load])

  const refresh = useCallback(async () => {
    await load()
  }, [load])

  // Hide the previous session's capability snapshot synchronously on callback.
  // Pages stay mounted with their drafts while the new bootstrap is pending.
  const current = loadedSession === currentSession
  const value = useMemo<WorkspaceContextValue>(
    () => ({
      status: authStatus === 'authenticated' && !current ? 'loading' : status,
      data: current ? data : undefined,
      errors,
      failure,
      requestId,
      traceId,
      stepUp,
      partial,
      forbidden,
      refresh,
    }),
    [
      authStatus,
      current,
      data,
      errors,
      failure,
      forbidden,
      partial,
      refresh,
      requestId,
      status,
      stepUp,
      traceId,
    ],
  )

  const requestableAccess = useMemo(
    () =>
      loadedSession && current && data?.effectivePermissions
        ? {
            session: loadedSession,
            scopes: data.effectivePermissions.requestableScopes,
          }
        : null,
    [loadedSession, current, data],
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
