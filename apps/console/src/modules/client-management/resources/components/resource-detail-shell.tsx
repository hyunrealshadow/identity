import { Button, Chip, Skeleton } from '@heroui/react'
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
  ConsoleResourceDocument,
  type ConsoleResourceQuery,
  type ConsoleResourceQueryVariables,
} from '#/gql/graphql'
import {
  failureDescriptionKey,
  failureTitleKey,
} from '#/lib/graphql/presentation'
import { useTranslator } from '#/lib/i18n'
import { useWorkspace } from '#/lib/workspace'
import { useConsoleQuery } from '#/modules/user-management/lib/console-query'
import { rbacScope } from '#/modules/user-management/lib/rbac-scope'

type Resource = NonNullable<ConsoleResourceQuery['resource']>
const ResourceContext = createContext<{
  resourceId: string
  resource: Resource | null
  canRead: boolean
} | null>(null)
export function useResourceContext() {
  const context = useContext(ResourceContext)
  if (!context) throw new Error('Resource detail context is missing')
  return context
}
export function ResourceDetailShell({ resourceId }: { resourceId: string }) {
  const t = useTranslator()
  const navigate = useNavigate()
  const workspace = useWorkspace()
  const scope = rbacScope(workspace.data?.effectivePermissions)
  const pathname = useRouterState({
    select: (state) => state.location.pathname,
  })
  const permissions = pathname.includes('/permissions')
  const variables = useMemo(
    () => (scope.resourcesRead ? { id: resourceId } : null),
    [resourceId, scope.resourcesRead],
  )
  const query = useConsoleQuery<
    ConsoleResourceQuery,
    ConsoleResourceQueryVariables
  >(
    ConsoleResourceDocument,
    variables,
    'ConsoleResource',
    Boolean(variables),
    'missing_resource',
  )
  const resource = query.data?.resource ?? null
  useBreadcrumbLabel(`/resources/${resourceId}`, resource?.name)
  return (
    <ResourceContext.Provider
      value={{ resourceId, resource, canRead: scope.resourcesRead }}
    >
      <header className="mb-6 space-y-5">
        <Button
          variant="ghost"
          size="sm"
          className="-ml-2"
          onPress={() => void navigate({ to: '/resources' })}
        >
          <ArrowLeft className="size-4" aria-hidden="true" />
          {t('resourcesBack')}
        </Button>
        <div className="space-y-2">
          <div className="flex flex-wrap items-center gap-3">
            <h1 className="text-2xl font-semibold tracking-tight">
              {resource?.name ??
                (scope.resourcesRead &&
                (query.status === 'idle' || query.status === 'loading') ? (
                  <Skeleton className="h-8 w-56 rounded-field" />
                ) : (
                  t('resourcesDetailTitle')
                ))}
            </h1>
            {resource ? (
              <Chip
                size="sm"
                variant="soft"
                color={resource.enabled ? 'success' : 'default'}
              >
                <Chip.Label>
                  {t(
                    resource.enabled
                      ? 'permissionsEnabled'
                      : 'permissionsDisabled',
                  )}
                </Chip.Label>
              </Chip>
            ) : null}
          </div>
          {resource ? (
            <div className="flex min-w-0 items-center gap-1 text-muted">
              <code className="break-all text-xs">{resource.uri}</code>
              <CopyButton value={resource.uri} label={t('audienceLabel')} />
            </div>
          ) : null}
        </div>
      </header>
      <nav
        aria-label={t('resourcesTabs')}
        className="mb-5 border-b border-separator"
      >
        <div className="flex gap-1">
          <Link
            to="/resources/$resourceId"
            params={{ resourceId }}
            className={
              'border-b-2 px-3 py-2.5 text-sm ' +
              (!permissions
                ? 'border-accent font-semibold'
                : 'border-transparent text-muted')
            }
            aria-current={!permissions ? 'page' : undefined}
          >
            {t('resourcesDetails')}
          </Link>
          <Link
            to="/resources/$resourceId/permissions"
            params={{ resourceId }}
            className={
              'border-b-2 px-3 py-2.5 text-sm ' +
              (permissions
                ? 'border-accent font-semibold'
                : 'border-transparent text-muted')
            }
            aria-current={permissions ? 'page' : undefined}
          >
            {t('resourcesPermissions')}
          </Link>
        </div>
      </nav>
      {query.status === 'error' ? (
        <AsyncState
          kind={query.forbidden ? 'forbidden' : 'error'}
          title={t(failureTitleKey(query.failure, query.forbidden))}
          description={t(failureDescriptionKey(query.failure, query.forbidden))}
          requestId={query.requestId}
          traceId={query.traceId}
          issues={query.errors}
          onRetry={() => void query.refresh()}
        />
      ) : query.status === 'ready' && !resource ? (
        <AsyncState kind="notFound" />
      ) : (
        <Outlet />
      )}
    </ResourceContext.Provider>
  )
}
