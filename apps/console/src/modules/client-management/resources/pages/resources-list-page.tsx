import { TableRowActions } from '#/components/table-row-actions'
import { CopyButton } from '#/components/copy-button'
import { Badge } from '@identity/ui/components/badge'
import { Button } from '@identity/ui/components/button'
import { Link, useNavigate } from '@tanstack/react-router'
import { useMemo } from 'react'
import { AsyncState } from '#/components/async-state'
import { CursorPagination } from '#/components/cursor-pagination'
import { PageHeader } from '#/components/page-header'
import { ResourceTable } from '#/components/resource-table'
import {
  ConsoleResourcesDocument,
  type ConsoleResourcesQuery,
  type ConsoleResourcesQueryVariables,
} from '#/generated/graphql'
import { formatDateTime } from '#/lib/format'
import {
  failureDescriptionKey,
  failureTitleKey,
} from '#/lib/graphql/presentation'
import { useLocale, useTranslator } from '#/lib/i18n'
import { useCursorPagination } from '#/lib/use-cursor-pagination'
import { useUrlFilters } from '#/lib/use-url-filters'
import { useWorkspace } from '#/lib/workspace'
import { ConsoleWorkspaceGate } from '#/modules/user-management/components/workspace-gate'
import { useConsoleQuery } from '#/lib/graphql/use-console-query'
import { rbacScope } from '#/modules/user-management/lib/rbac-scope'
import { RbacAccessRestricted } from '#/modules/user-management/roles/components/role-access'
import {
  UserSelectField,
  UserTextField,
} from '#/modules/user-management/users/components/user-form-fields'
import {
  RESOURCES_PAGE_SIZE,
  resourcesAppliedFilters,
  resourcesQueryVariables,
  resourcesSearchKey,
  type ResourcesFilters,
  type ResourcesSearch,
} from '../lib/resources-search'

export function ResourcesListPage({ search }: { search: ResourcesSearch }) {
  const t = useTranslator()
  const { locale, timeZone } = useLocale()
  const navigate = useNavigate()
  const workspace = useWorkspace()
  const scope = rbacScope(workspace.data?.effectivePermissions)
  // The URL always mirrors the filter form; queries use the applied filters.
  const { applied, go } = useUrlFilters<ResourcesSearch, ResourcesFilters>({
    search,
    keyOf: resourcesSearchKey,
    appliedOf: resourcesAppliedFilters,
    navigate: (next, { replace }) =>
      void navigate({ to: '/resources', search: next, replace }),
  })
  const appliedSearch: ResourcesSearch = {
    ...applied,
    order: search.order,
    size: search.size,
    after: search.after,
    before: search.before,
  }
  const appliedKey = resourcesSearchKey(appliedSearch)
  const variables = useMemo(
    () => (scope.resourcesRead ? resourcesQueryVariables(appliedSearch) : null),
    [scope.resourcesRead, appliedKey],
  )
  const query = useConsoleQuery<
    ConsoleResourcesQuery,
    ConsoleResourcesQueryVariables
  >(
    ConsoleResourcesDocument,
    variables,
    Boolean(variables),
    'missing_resource_connection',
    { keepPreviousData: true },
  )
  const connection = query.data?.resources
  const pager = useCursorPagination({
    search,
    variables,
    onNavigate: (cursor) =>
      go({ ...search, after: undefined, before: undefined, ...cursor }),
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

            onBack={() => void navigate({ to: '/' })}
            backLabel="goHome"
          />
        ) : (
          <section className="space-y-5">
            <ResourceTable
              id="resources"
              label={t('resourcesTable')}
              filters={
                <form
                  className="flex flex-wrap items-start gap-2"
                  onSubmit={(event) => {
                    event.preventDefault()
                    const filters = resourcesAppliedFilters(search)
                    const next: ResourcesSearch = {
                      ...search,
                      ...filters,
                      after: undefined,
                      before: undefined,
                    }
                    // Applying the filters already in effect reloads them.
                    if (resourcesSearchKey(next) === appliedKey)
                      void query.refresh()
                    go(next, { apply: filters })
                  }}
                >
                  <div className="w-full sm:w-72">
                    <UserTextField
                      name="resource-search"
                      label={t('resourcesSearch')}
                      hideLabel
                      value={search.q ?? ''}
                      onChange={(value) =>
                        go({ ...search, q: value || undefined }, { replace: true })
                      }
                      placeholder={t('resourcesSearchPlaceholder')}
                    />
                  </div>
                  <div className="w-36">
                    <UserSelectField
                      name="resource-status"
                      label={t('resourcesStatus')}
                      hideLabel
                      value={search.enabled ?? 'any'}
                      onChange={(value) =>
                        go(
                          {
                            ...search,
                            enabled:
                              value === 'enabled' || value === 'disabled'
                                ? value
                                : undefined,
                          },
                          { replace: true },
                        )
                      }
                      options={[
                        { id: 'any', label: t('permissionsFilterAny') },
                        { id: 'enabled', label: t('permissionsEnabled') },
                        { id: 'disabled', label: t('permissionsDisabled') },
                      ]}
                    />
                  </div>
                  <Button type="submit" variant="outline">
                    {t('resourcesFilter')}
                  </Button>
                  <Button
                    variant="ghost"
                    onClick={() => go({ size: search.size }, { apply: {} })}
                  >
                    {t('resourcesReset')}
                  </Button>
                </form>
              }
              items={(connection?.edges ?? []).map(({ node }) => node)}
              order={search.order}
              onOrderChange={(order) =>
                go({
                    ...search,
                    order: order as ResourcesSearch['order'],
                    after: undefined,
                    before: undefined,
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
                    pageSize={search.size ?? RESOURCES_PAGE_SIZE}
                    onPageSizeChange={(size) =>
                      go({ ...search, size, after: undefined, before: undefined })
                    }
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
                    <Badge
                      variant="secondary"
                      className={resource.enabled ? 'text-success' : undefined}
                    >
                      {t(
                        resource.enabled
                          ? 'permissionsEnabled'
                          : 'permissionsDisabled',
                      )}
                    </Badge>
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
