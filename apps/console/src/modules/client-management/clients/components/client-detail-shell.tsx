import { Button, Skeleton } from '@heroui/react'
import {
  Link,
  Outlet,
  useNavigate,
  useRouterState,
} from '@tanstack/react-router'
import { ArrowLeft } from 'lucide-react'
import { createContext, useContext, useMemo } from 'react'

import { AsyncState } from '#/components/async-state'
import { useBreadcrumbLabel } from '#/components/app-breadcrumbs'
import { CopyButton } from '#/components/copy-button'
import {
  ConsoleClientDocument,
  type ConsoleClientQuery,
  type ConsoleClientQueryVariables,
} from '#/gql/graphql'
import {
  failureDescriptionKey,
  failureTitleKey,
} from '#/lib/graphql/presentation'
import { useLocale, useTranslator, type MessageKey } from '#/lib/i18n'
import { useWorkspace } from '#/lib/workspace'
import {
  useConsoleQuery,
  type ConsoleQueryState,
} from '#/modules/user-management/lib/console-query'
import { resolveLocalizedText } from '#/modules/user-management/groups/lib/groups-search'
import { RbacAccessRestricted } from '#/modules/user-management/roles/components/role-access'
import { clientScope, type ClientScope } from '../lib/client-scope'
import { ClientBuiltInChip, ClientStatusChip } from './client-status'

export type ConsoleClient = NonNullable<ConsoleClientQuery['client']>

interface ClientDetailContextValue {
  clientId: string
  client: ConsoleClient | null
  query: ConsoleQueryState<ConsoleClientQuery>
  scope: ClientScope
}

const ClientDetailContext = createContext<ClientDetailContextValue | null>(null)

export function useClientDetail() {
  const value = useContext(ClientDetailContext)
  if (!value) throw new Error('Client detail context is missing')
  return value
}

const tabs: ReadonlyArray<{
  to: '/clients/$clientId' | '/clients/$clientId/credentials' | '/clients/$clientId/scopes'
  label: MessageKey
  match: (path: string) => boolean
}> = [
  {
    to: '/clients/$clientId',
    label: 'clientsTabOverview',
    match: (path) => !/\/(credentials|scopes)$/u.test(path),
  },
  {
    to: '/clients/$clientId/credentials',
    label: 'clientsTabCredentials',
    match: (path) => path.endsWith('/credentials'),
  },
  {
    to: '/clients/$clientId/scopes',
    label: 'clientsTabScopes',
    match: (path) => path.endsWith('/scopes'),
  },
]

export function ClientDetailShell({ clientId }: { clientId: string }) {
  const t = useTranslator()
  const { locale } = useLocale()
  const navigate = useNavigate()
  const workspace = useWorkspace()
  const scope = useMemo(
    () => clientScope(workspace.data?.effectivePermissions),
    [workspace.data?.effectivePermissions],
  )
  const pathname = useRouterState({ select: (state) => state.location.pathname })
  const variables = useMemo(
    () => (scope.read ? { id: clientId } : null),
    [clientId, scope.read],
  )
  const query = useConsoleQuery<ConsoleClientQuery, ConsoleClientQueryVariables>(
    ConsoleClientDocument,
    variables,
    'ConsoleClient',
    Boolean(variables),
    'missing_client',
  )
  const client = query.data?.client ?? null
  const name = client
    ? (resolveLocalizedText(client.names, locale) ?? client.name)
    : undefined
  useBreadcrumbLabel(`/clients/${clientId}`, name)
  const loading = query.status === 'idle' || query.status === 'loading'

  return (
    <ClientDetailContext.Provider value={{ clientId, client, query, scope }}>
      <header className="mb-6 space-y-5">
        <Button
          variant="ghost"
          size="sm"
          className="-ml-2"
          onPress={() => void navigate({ to: '/clients' })}
        >
          <ArrowLeft className="size-4" aria-hidden="true" />
          {t('clientsBack')}
        </Button>
        <div className="space-y-2">
          <div className="flex flex-wrap items-center gap-3">
            <h1 className="text-2xl font-semibold tracking-tight">
              {name ??
                (scope.read && loading ? (
                  <Skeleton className="h-8 w-56 rounded-field" />
                ) : (
                  t('clientsDetailTitle')
                ))}
            </h1>
            {client ? <ClientStatusChip enabled={client.enabled} /> : null}
            {client?.builtIn ? <ClientBuiltInChip /> : null}
          </div>
          {client ? (
            <div className="flex min-w-0 items-center gap-1 text-muted">
              <span className="text-xs">{t('clientsClientId')}</span>
              <code className="break-all text-xs">{client.clientId}</code>
              <CopyButton value={client.clientId} label={t('clientsClientId')} />
            </div>
          ) : scope.read && loading ? (
            <Skeleton className="h-4 w-80 rounded-field" />
          ) : null}
        </div>
      </header>
      <nav aria-label={t('clientsTabs')} className="mb-5 border-b border-separator">
        <div className="flex gap-1">
          {tabs.map((tab) => {
            const active = tab.match(pathname)
            return (
              <Link
                key={tab.to}
                to={tab.to}
                params={{ clientId }}
                className={
                  'border-b-2 px-3 py-2.5 text-sm ' +
                  (active
                    ? 'border-accent font-semibold'
                    : 'border-transparent text-muted')
                }
                aria-current={active ? 'page' : undefined}
              >
                {t(tab.label)}
              </Link>
            )
          })}
        </div>
      </nav>
      {!scope.read ? (
        <RbacAccessRestricted
          title="clientsNoReadTitle"
          description="clientsNoReadDescription"
          onBack={() => void navigate({ to: '/' })}
          backLabel="goHome"
        />
      ) : query.status === 'error' ? (
        <AsyncState
          kind={query.forbidden ? 'forbidden' : 'error'}
          title={t(failureTitleKey(query.failure, query.forbidden))}
          description={t(failureDescriptionKey(query.failure, query.forbidden))}
          requestId={query.requestId}
          traceId={query.traceId}
          issues={query.errors}
          onRetry={() => void query.refresh()}
        />
      ) : query.status === 'ready' && !client ? (
        <AsyncState kind="notFound" title={t('clientsNotFound')} />
      ) : (
        <Outlet />
      )}
    </ClientDetailContext.Provider>
  )
}
