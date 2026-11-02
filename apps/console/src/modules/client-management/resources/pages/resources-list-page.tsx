import { TableRowActions } from '#/components/table-row-actions'
import { CopyButton } from '#/components/copy-button'
import { Button, Chip } from '@heroui/react'
import { Link, useNavigate } from '@tanstack/react-router'
import { useEffect, useMemo, useState } from 'react'
import { AsyncState } from '#/components/async-state'
import { CursorPagination } from '#/components/cursor-pagination'
import { PageHeader } from '#/components/page-header'
import { ResourceTable } from '#/components/resource-table'
import {
  ConsoleResourcesDocument,
  type ConsoleResourcesQuery,
  type ConsoleResourcesQueryVariables,
} from '#/gql/graphql'
import { formatDateTime } from '#/lib/format'
import {
  failureDescriptionKey,
  failureTitleKey,
} from '#/lib/graphql/presentation'
import { useLocale, useTranslator } from '#/lib/i18n'
import { useCursorPagination } from '#/lib/use-cursor-pagination'
import { useWorkspace } from '#/lib/workspace'
import { ConsoleWorkspaceGate } from '#/modules/user-management/components/workspace-gate'
import { useConsoleQuery } from '#/modules/user-management/lib/console-query'
import { rbacScope } from '#/modules/user-management/lib/rbac-scope'
import { RbacAccessRestricted } from '#/modules/user-management/roles/components/role-access'
import {
  UserSelectField,
  UserTextField,
} from '#/modules/user-management/users/components/user-form-fields'
import {
  resourcesQueryVariables,
  type ResourcesSearch,
} from '../lib/resources-search'

export function ResourcesListPage({ search }: { search: ResourcesSearch }) {
  const t = useTranslator()
  const { locale, timeZone } = useLocale()
  const navigate = useNavigate()
  const workspace = useWorkspace()
  const scope = rbacScope(workspace.data?.effectivePermissions)
  const [q, setQ] = useState(search.q ?? '')
  const [enabled, setEnabled] = useState(search.enabled ?? 'any')
  useEffect(() => {
    setQ(search.q ?? '')
    setEnabled(search.enabled ?? 'any')
  }, [search.q, search.enabled])
  const variables = useMemo(
    () => (scope.resourcesRead ? resourcesQueryVariables(search) : null),
    [
      scope.resourcesRead,
      search.q,
      search.enabled,
      search.order,
      search.after,
      search.before,
    ],
  )
  const query = useConsoleQuery<
    ConsoleResourcesQuery,
    ConsoleResourcesQueryVariables
  >(
    ConsoleResourcesDocument,
    variables,
    'ConsoleResources',
    Boolean(variables),
    'missing_resource_connection',
  )
  const connection = query.data?.resources
  const pager = useCursorPagination({
    search,
    variables,
    onNavigate: (cursor) =>
      void navigate({
        to: '/resources',
        search: { ...search, after: undefined, before: undefined, ...cursor },
      }),
  })
  return (
    <>
      <PageHeader
        title={t('resourcesTitle')}
        description={t('resourcesDescription')}
      />
      <ConsoleWorkspaceGate>
        {!scope.resourcesRead ? (
          <RbacAccessRestricted
            title="forbiddenTitle"
            description="forbiddenDescription"
            stepUp={scope.resourcesReadStepUp}
            onBack={() => void navigate({ to: '/' })}
            backLabel="goHome"
          />
        ) : (
          <section className="space-y-5">
            <form
              className="collection-filter-controls flex flex-wrap items-end gap-3"
              onSubmit={(event) => {
                event.preventDefault()
                void navigate({
                  to: '/resources',
                  search: {
                    q: q.trim() || undefined,
                    enabled:
                      enabled === 'any'
                        ? undefined
                        : (enabled as ResourcesSearch['enabled']),
                    order: search.order,
                  },
                })
              }}
            >
              <div className="min-w-48 flex-1">
                <UserTextField
                  name="resource-search"
                  label={t('resourcesSearch')}
                  value={q}
                  onChange={setQ}
                  placeholder={t('resourcesSearchPlaceholder')}
                />
              </div>
              <div className="w-40">
                <UserSelectField
                  name="resource-status"
                  label={t('resourcesStatus')}
                  value={enabled}
                  onChange={(value) => setEnabled(value as typeof enabled)}
                  options={[
                    { id: 'any', label: t('permissionsFilterAny') },
                    { id: 'enabled', label: t('permissionsEnabled') },
                    { id: 'disabled', label: t('permissionsDisabled') },
                  ]}
                />
              </div>
              <Button type="submit" variant="secondary">
                {t('resourcesFilter')}
              </Button>
              <Button
                variant="ghost"
                onPress={() => void navigate({ to: '/resources', search: {} })}
              >
                {t('resourcesReset')}
              </Button>
            </form>
            <ResourceTable
              id="resources"
              label={t('resourcesTable')}
              items={(connection?.edges ?? []).map(({ node }) => node)}
              order={search.order}
              onOrderChange={(order) =>
                void navigate({
                  to: '/resources',
                  search: {
                    ...search,
                    order: order as ResourcesSearch['order'],
                    after: undefined,
                    before: undefined,
                  },
                })
              }
              onRefresh={() => void query.refresh()}
              refreshing={query.refreshing || query.status === 'loading'}
              emptyState={
                query.status === 'error' ? (
                  <AsyncState
                    kind={query.forbidden ? 'forbidden' : 'error'}
                    title={t(failureTitleKey(query.failure, query.forbidden))}
                    description={t(
                      failureDescriptionKey(query.failure, query.forbidden),
                    )}
                    requestId={query.requestId}
                    traceId={query.traceId}
                    issues={query.errors}
                    onRetry={() => void query.refresh()}
                  />
                ) : (
                  <AsyncState
                    kind="empty"
                    compact
                    title={t('resourcesEmpty')}
                  />
                )
              }
              pagination={
                connection ? (
                  <CursorPagination
                    label={t('resourcesTable')}
                    pageCount={connection.edges.length}
                    pageInfo={connection.pageInfo}
                    controller={pager}
                    isDisabled={query.refreshing}
                  />
                ) : null
              }
              columns={[
                {
                  id: 'name',
                  label: t('resourcesName'),
                  primary: true,
                  sort: 'NAME',
                  render: (resource) => (
                    <Link
                      to="/resources/$resourceId"
                      params={{ resourceId: resource.id }}
                      className="font-medium hover:underline"
                    >
                      {resource.name}
                    </Link>
                  ),
                },
                {
                  id: 'uri',
                  label: t('resourcesIdentifier'),
                  sort: 'URI',
                  render: (resource) => (
                    <div className="flex items-center gap-1">
                      <code className="break-all text-xs">{resource.uri}</code>
                      <CopyButton
                        value={resource.uri}
                        label={t('audienceLabel')}
                      />
                    </div>
                  ),
                },
                {
                  id: 'status',
                  label: t('resourcesStatus'),
                  render: (resource) => (
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
                  ),
                },
                {
                  id: 'created',
                  label: t('tableColumnCreated'),
                  sort: 'CREATED_AT',
                  render: (resource) => (
                    <span className="whitespace-nowrap text-sm">
                      {formatDateTime(resource.createdAt, locale, timeZone)}
                    </span>
                  ),
                },
                {
                  id: 'actions',
                  label: t('permissionsColumnActions'),
                  render: (resource) => (
                    <TableRowActions
                      subject={resource.name}
                      actions={[
                        {
                          id: 'permissions',
                          label: t('resourcesPermissions'),
                          onAction: () => {
                            void navigate({
                              to: '/resources/$resourceId/permissions',
                              params: { resourceId: resource.id },
                            })
                          },
                        },
                      ]}
                    />
                  ),
                },
              ]}
            />
          </section>
        )}
      </ConsoleWorkspaceGate>
    </>
  )
}
