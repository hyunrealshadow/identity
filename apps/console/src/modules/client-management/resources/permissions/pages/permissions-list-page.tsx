import { Button, Chip } from '@heroui/react'
import { Link, useNavigate } from '@tanstack/react-router'
import { useEffect, useMemo, useState } from 'react'
import { AsyncState } from '#/components/async-state'
import { CopyButton } from '#/components/copy-button'
import { CursorPagination } from '#/components/cursor-pagination'
import { ResourceTable, type ResourceColumn } from '#/components/resource-table'
import { type ConsoleResourcePermissionsQueryVariables } from '#/generated/graphql'
import { formatDateTime } from '#/lib/format'
import {
  failureTitleKey,
  failureDescriptionKey,
} from '#/lib/graphql/presentation'
import { useLocale, useTranslator } from '#/lib/i18n'
import { useCursorPagination } from '#/lib/use-cursor-pagination'
import { useWorkspace } from '#/lib/workspace'
import { useResourceContext } from '../../components/resource-detail-shell'
import { ConsoleWorkspaceGate } from '#/modules/user-management/components/workspace-gate'
import { rbacScope } from '#/modules/user-management/lib/rbac-scope'
import { RbacAccessRestricted } from '#/modules/user-management/roles/components/role-access'
import { PermissionBuiltInChip } from '#/modules/user-management/roles/components/role-status'
import {
  UserTextField,
  UserSelectField,
} from '#/modules/user-management/users/components/user-form-fields'
import {
  permissionDisplayDescription,
  permissionDisplayName,
  withPermissionDisplayFields,
} from '#/modules/user-management/roles/lib/role-localization'
import { usePermissionList } from '../hooks/use-permissions'
import {
  permissionsFilterDraft,
  permissionsSearchForResource,
  resourcePermissionsQueryVariables,
  permissionsSearchFromDraft,
  isPermissionOrder,
  type PermissionsSearch,
} from '../lib/permissions-search'

export function PermissionsListPage({
  resourceId,
  search: routeSearch,
}: {
  resourceId: string
  search: PermissionsSearch
}) {
  const t = useTranslator()
  const { locale, timeZone } = useLocale()
  const navigate = useNavigate()
  const workspace = useWorkspace()
  const scope = rbacScope(workspace.data?.effectivePermissions)
  const { resource } = useResourceContext()
  const readOnly = !resource || resource.uri === 'urn:identity:graphql'
  const search = permissionsSearchForResource(routeSearch, readOnly)
  const [draft, setDraft] = useState(() => permissionsFilterDraft(search))
  useEffect(
    () => setDraft(permissionsFilterDraft(search)),
    [search.q, search.enabled, search.builtIn, search.order],
  )
  const variables =
    useMemo<ConsoleResourcePermissionsQueryVariables | null>(() => {
      if (!scope.permissionRead || (scope.resourcesRead && !resource))
        return null
      return resourcePermissionsQueryVariables(
        resourceId,
        search,
      ) as ConsoleResourcePermissionsQueryVariables
    }, [
      resourceId,
      resource,
      scope.resourcesRead,
      scope.permissionRead,
      search.q,
      search.enabled,
      search.builtIn,
      search.order,
      search.after,
      search.before,
    ])
  const query = usePermissionList(variables, Boolean(variables))
  const connection = query.data?.permissions
  const canCreate = scope.permissionWrite && !readOnly
  const pager = useCursorPagination({
    search,
    variables,
    onNavigate: (cursor) =>
      void navigate({
        to: '/resources/$resourceId/permissions',
        params: { resourceId },
        search: {
          ...search,
          resourceId: undefined,
          after: undefined,
          before: undefined,
          ...cursor,
        },
      }),
  })
  return (
    <ConsoleWorkspaceGate>
      {!scope.permissionRead ? (
        <RbacAccessRestricted
          title="permissionsNoReadTitle"
          description="permissionsNoReadWriteOnlyDescription"

          onBack={() => void navigate({ to: '/resources' })}
          backLabel="resourcesBack"
        />
      ) : (
        <section className="space-y-5">
          <div className="flex flex-wrap items-center justify-between gap-3">
            <p className="text-sm text-muted">
              {t('resourcePermissionsDescription')}
            </p>
            {canCreate ? (
              <Button
                onPress={() =>
                  void navigate({
                    to: '/resources/$resourceId/permissions/new',
                    params: { resourceId },
                  })
                }
              >
                {t('permissionsNewAction')}
              </Button>
            ) : null}
          </div>
          <form
            className="collection-filter-controls flex flex-wrap items-end gap-3"
            onSubmit={(event) => {
              event.preventDefault()
              void navigate({
                to: '/resources/$resourceId/permissions',
                params: { resourceId },
                search: {
                  ...permissionsSearchFromDraft(draft),
                  resourceId: undefined,
                },
              })
            }}
          >
            <div className="min-w-48 flex-1">
              <UserTextField
                name="permission-search"
                label={t('permissionsFilterSearchLabel')}
                placeholder={t('permissionsFilterSearchPlaceholder')}
                value={draft.q}
                onChange={(q) => setDraft({ ...draft, q })}
              />
            </div>
            {!readOnly ? (
              <div className="w-40">
                <UserSelectField
                  name="permission-status"
                  label={t('permissionsFilterStatusLabel')}
                  value={draft.enabled}
                  onChange={(enabled) =>
                    setDraft({
                      ...draft,
                      enabled: enabled as typeof draft.enabled,
                    })
                  }
                  options={[
                    { id: 'any', label: t('permissionsFilterAny') },
                    { id: 'enabled', label: t('permissionsEnabled') },
                    { id: 'disabled', label: t('permissionsDisabled') },
                  ]}
                />
              </div>
            ) : null}
            <Button type="submit" variant="secondary">
              {t('resourcesFilter')}
            </Button>
            <Button
              variant="ghost"
              onPress={() =>
                void navigate({
                  to: '/resources/$resourceId/permissions',
                  params: { resourceId },
                  search: {},
                })
              }
            >
              {t('resourcesReset')}
            </Button>
          </form>
          <ResourceTable
            id="resource-permissions"
            density="compact"
            maxHeight="clamp(12rem, calc(100dvh - 34rem), 30rem)"
            label={t('permissionsTableLabel')}
            items={(connection?.edges ?? []).map(({ node }) => node)}
            order={search.order}
            onOrderChange={(order) =>
              void navigate({
                to: '/resources/$resourceId/permissions',
                params: { resourceId },
                search: {
                  ...search,
                  resourceId: undefined,
                  order: isPermissionOrder(order) ? order : undefined,
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
                  title={t('permissionsEmptyTitle')}
                />
              )
            }
            pagination={
              connection ? (
                <CursorPagination
                  label={t('permissionsPaginationLabel')}
                  pageCount={connection.edges.length}
                  totalCount={connection.totalCount}
                  pageInfo={connection.pageInfo}
                  controller={pager}
                  isDisabled={query.refreshing}
                />
              ) : null
            }
            columns={[
              {
                id: 'permission',
                label: t('permissionsColumnPermission'),
                primary: true,
                sort: 'CODE',
                render: (permission) => (
                  <div className="min-w-48">
                    <div className="flex items-center gap-2">
                      <Link
                        to="/resources/$resourceId/permissions/$permissionId"
                        params={{ resourceId, permissionId: permission.id }}
                        className="font-mono text-sm hover:underline"
                      >
                        {permission.code}
                      </Link>
                      <CopyButton
                        value={permission.code}
                        label={t('permissionCodeLabel')}
                      />
                      {!readOnly ? (
                        <PermissionBuiltInChip builtIn={permission.builtIn} />
                      ) : null}
                    </div>
                    <p className="mt-1 text-xs text-muted">
                      {permissionDisplayName(
                        withPermissionDisplayFields(permission),
                        locale,
                      )}
                    </p>
                  </div>
                ),
              },
              {
                id: 'description',
                label: t('rbacPermissionDescription'),
                render: (permission) => (
                  <span className="text-sm text-muted">
                    {permissionDisplayDescription(
                      withPermissionDisplayFields(permission),
                      locale,
                    )}
                  </span>
                ),
              },
              ...(!readOnly
                ? ([
                    {
                      id: 'status',
                      label: t('resourcesStatus'),
                      render: (permission) => (
                        <Chip
                          size="sm"
                          variant="soft"
                          color={permission.enabled ? 'success' : 'default'}
                        >
                          <Chip.Label>
                            {t(
                              permission.enabled
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
                      render: (permission) => (
                        <span className="whitespace-nowrap text-sm">
                          {formatDateTime(
                            permission.createdAt,
                            locale,
                            timeZone,
                          )}
                        </span>
                      ),
                    },
                  ] satisfies ResourceColumn<
                    NonNullable<typeof connection>['edges'][number]['node']
                  >[])
                : []),
            ]}
          />
        </section>
      )}
    </ConsoleWorkspaceGate>
  )
}
