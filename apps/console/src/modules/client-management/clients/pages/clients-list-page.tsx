import { Button } from '@identity/ui/components/button'
import { Link, useNavigate } from '@tanstack/react-router'
import { Plus } from 'lucide-react'
import { useMemo } from 'react'

import { AsyncState } from '#/components/async-state'
import { CopyButton } from '#/components/copy-button'
import { CursorPagination } from '#/components/cursor-pagination'
import { PageHeader } from '#/components/page-header'
import { ResourceTable } from '#/components/resource-table'
import { TableRowActions } from '#/components/table-row-actions'
import {
  ConsoleClientsDocument,
  type ConsoleClientsQuery,
  type ConsoleClientsQueryVariables,
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
import { resolveLocalizedText } from '#/modules/user-management/groups/lib/groups-search'
import { useConsoleQuery } from '#/lib/graphql/use-console-query'
import { RbacAccessRestricted } from '#/modules/user-management/roles/components/role-access'
import {
  UserSelectField,
  UserTextField,
} from '#/modules/user-management/users/components/user-form-fields'
import { ClientBuiltInChip, ClientStatusChip } from '../components/client-status'
import { clientScope } from '../lib/client-scope'
import {
  CLIENTS_PAGE_SIZE,
  clientsAppliedFilters,
  clientsQueryVariables,
  clientsSearchKey,
  type ClientsFilters,
  type ClientsSearch,
} from '../lib/clients-search'

export function ClientsListPage({ search }: { search: ClientsSearch }) {
  const t = useTranslator()
  const { locale, timeZone } = useLocale()
  const navigate = useNavigate()
  const workspace = useWorkspace()
  const scope = useMemo(
    () => clientScope(workspace.data?.effectivePermissions),
    [workspace.data?.effectivePermissions],
  )
  // The URL always mirrors the filter form; queries use the applied filters.
  const { applied, go } = useUrlFilters<ClientsSearch, ClientsFilters>({
    search,
    keyOf: clientsSearchKey,
    appliedOf: clientsAppliedFilters,
    navigate: (next, { replace }) =>
      void navigate({ to: '/clients', search: next, replace }),
  })
  const appliedSearch: ClientsSearch = {
    ...applied,
    order: search.order,
    size: search.size,
    after: search.after,
    before: search.before,
  }
  const appliedKey = clientsSearchKey(appliedSearch)
  const variables = useMemo(
    () => (scope.read ? clientsQueryVariables(appliedSearch) : null),
    [scope.read, appliedKey],
  )
  const query = useConsoleQuery<ConsoleClientsQuery, ConsoleClientsQueryVariables>(
    ConsoleClientsDocument,
    variables,
    Boolean(variables),
    'missing_client_connection',
    { keepPreviousData: true },
  )
  const connection = query.data?.clients
  const pager = useCursorPagination({
    search,
    variables,
    onNavigate: (cursor) =>
      go({ ...search, after: undefined, before: undefined, ...cursor }),
  })

  return (
    <>
      <PageHeader
        title={t('clientsTitle')}
        description={t('clientsDescription')}
        actions={
          scope.create ? (
            <Button onClick={() => void navigate({ to: '/clients/new' })}>
              <Plus className="size-4" aria-hidden="true" />
              {t('clientsNew')}
            </Button>
          ) : null
        }
      />
      <ConsoleWorkspaceGate>
        {!scope.read ? (
          <RbacAccessRestricted
            title="clientsNoReadTitle"
            description="clientsNoReadDescription"
            onBack={() => void navigate({ to: '/' })}
            backLabel="goHome"
          />
        ) : (
          <section className="space-y-5">
            <ResourceTable
              id="clients"
              label={t('clientsTable')}
              filters={
                <form
                  className="flex flex-wrap items-start gap-2"
                  onSubmit={(event) => {
                    event.preventDefault()
                    const filters = clientsAppliedFilters(search)
                    const next: ClientsSearch = {
                      ...search,
                      ...filters,
                      after: undefined,
                      before: undefined,
                    }
                    // Applying the filters already in effect reloads them.
                    if (clientsSearchKey(next) === appliedKey)
                      void query.refresh()
                    go(next, { apply: filters })
                  }}
                >
                  <div className="w-full sm:w-72">
                    <UserTextField
                      name="client-search"
                      label={t('clientsSearch')}
                      hideLabel
                      value={search.q ?? ''}
                      onChange={(value) =>
                        go({ ...search, q: value || undefined }, { replace: true })
                      }
                      placeholder={t('clientsSearchPlaceholder')}
                    />
                  </div>
                  <div className="w-36">
                    <UserSelectField
                      name="client-status"
                      label={t('clientsStatus')}
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
                        { id: 'any', label: t('clientsFilterAny') },
                        { id: 'enabled', label: t('clientsEnabled') },
                        { id: 'disabled', label: t('clientsDisabled') },
                      ]}
                    />
                  </div>
                  <Button type="submit" variant="outline">
                    {t('clientsFilter')}
                  </Button>
                  <Button
                    variant="ghost"
                    onClick={() => go({ size: search.size }, { apply: {} })}
                  >
                    {t('clientsReset')}
                  </Button>
                </form>
              }
              items={(connection?.edges ?? []).map(({ node }) => node)}
              order={search.order}
              onOrderChange={(order) =>
                go({
                    ...search,
                    order: order as ClientsSearch['order'],
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
                  <AsyncState kind="empty" compact title={t('clientsEmpty')} />
                )
              }
              pagination={
                connection ? (
                  <CursorPagination
                    label={t('clientsTable')}
                    pageCount={connection.edges.length}
                    totalCount={connection.totalCount}
                    pageInfo={connection.pageInfo}
                    controller={pager}
                    isDisabled={query.refreshing}
                    pageSize={search.size ?? CLIENTS_PAGE_SIZE}
                    onPageSizeChange={(size) =>
                      go({ ...search, size, after: undefined, before: undefined })
                    }
                  />
                ) : null
              }
              columns={[
                {
                  id: 'name',
                  label: t('clientsName'),
                  primary: true,
                  sort: 'NAME',
                  render: (client) => (
                    <div className="flex flex-wrap items-center gap-2">
                      <Link
                        to="/clients/$clientId"
                        params={{ clientId: client.id }}
                        className="font-medium hover:underline"
                      >
                        {resolveLocalizedText(client.names, locale) ?? client.name}
                      </Link>
                      {client.builtIn ? <ClientBuiltInChip /> : null}
                    </div>
                  ),
                },
                {
                  id: 'clientId',
                  label: t('clientsClientId'),
                  render: (client) => (
                    <div className="flex items-center gap-1">
                      <code className="break-all text-xs">{client.id}</code>
                      <CopyButton value={client.id} label={t('clientsClientId')} />
                    </div>
                  ),
                },
                {
                  id: 'status',
                  label: t('clientsStatus'),
                  render: (client) => <ClientStatusChip enabled={client.enabled} />,
                },
                {
                  id: 'created',
                  label: t('tableColumnCreated'),
                  sort: 'CREATED_AT',
                  render: (client) => (
                    <span className="whitespace-nowrap text-sm">
                      {formatDateTime(client.createdAt, locale, timeZone)}
                    </span>
                  ),
                },
                {
                  id: 'actions',
                  label: t('clientsColumnActions'),
                  render: (client) => (
                    <TableRowActions
                      subject={resolveLocalizedText(client.names, locale) ?? client.name}
                      actions={[
                        {
                          id: 'open',
                          label: t('clientsOpen'),
                          onAction: () =>
                            void navigate({
                              to: '/clients/$clientId',
                              params: { clientId: client.id },
                            }),
                        },
                        ...(scope.credentialsRead
                          ? [
                              {
                                id: 'credentials',
                                label: t('clientsTabCredentials'),
                                onAction: () =>
                                  void navigate({
                                    to: '/clients/$clientId/credentials',
                                    params: { clientId: client.id },
                                  }),
                              },
                            ]
                          : []),
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
