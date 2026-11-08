import { Button } from '@identity/ui/components/button'
import { Link, useNavigate } from '@tanstack/react-router'
import { Plus } from 'lucide-react'
import { useEffect, useMemo, useState } from 'react'

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
import { clientsQueryVariables, type ClientsSearch } from '../lib/clients-search'

export function ClientsListPage({ search }: { search: ClientsSearch }) {
  const t = useTranslator()
  const { locale, timeZone } = useLocale()
  const navigate = useNavigate()
  const workspace = useWorkspace()
  const scope = useMemo(
    () => clientScope(workspace.data?.effectivePermissions),
    [workspace.data?.effectivePermissions],
  )
  const [q, setQ] = useState(search.q ?? '')
  const [enabled, setEnabled] = useState<string>(search.enabled ?? 'any')
  useEffect(() => {
    setQ(search.q ?? '')
    setEnabled(search.enabled ?? 'any')
  }, [search.q, search.enabled])
  const variables = useMemo(
    () => (scope.read ? clientsQueryVariables(search) : null),
    [scope.read, search.q, search.enabled, search.order, search.after, search.before],
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
      void navigate({
        to: '/clients',
        search: { ...search, after: undefined, before: undefined, ...cursor },
      }),
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
            <form
              className="collection-filter-controls flex flex-wrap items-end gap-3"
              onSubmit={(event) => {
                event.preventDefault()
                void navigate({
                  to: '/clients',
                  search: {
                    q: q.trim() || undefined,
                    enabled:
                      enabled === 'enabled' || enabled === 'disabled'
                        ? enabled
                        : undefined,
                    order: search.order,
                  },
                })
              }}
            >
              <div className="min-w-48 flex-1">
                <UserTextField
                  name="client-search"
                  label={t('clientsSearch')}
                  value={q}
                  onChange={setQ}
                  placeholder={t('clientsSearchPlaceholder')}
                />
              </div>
              <div className="w-40">
                <UserSelectField
                  name="client-status"
                  label={t('clientsStatus')}
                  value={enabled}
                  onChange={setEnabled}
                  options={[
                    { id: 'any', label: t('clientsFilterAny') },
                    { id: 'enabled', label: t('clientsEnabled') },
                    { id: 'disabled', label: t('clientsDisabled') },
                  ]}
                />
              </div>
              <Button type="submit" variant="secondary">
                {t('clientsFilter')}
              </Button>
              <Button
                variant="ghost"
                onClick={() => void navigate({ to: '/clients', search: {} })}
              >
                {t('clientsReset')}
              </Button>
            </form>
            <ResourceTable
              id="clients"
              label={t('clientsTable')}
              items={(connection?.edges ?? []).map(({ node }) => node)}
              order={search.order}
              onOrderChange={(order) =>
                void navigate({
                  to: '/clients',
                  search: {
                    ...search,
                    order: order as ClientsSearch['order'],
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
                  <AsyncState kind="empty" compact title={t('clientsEmpty')} />
                )
              }
              pagination={
                connection ? (
                  <CursorPagination
                    label={t('clientsTable')}
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
                      <code className="break-all text-xs">{client.clientId}</code>
                      <CopyButton value={client.clientId} label={t('clientsClientId')} />
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
