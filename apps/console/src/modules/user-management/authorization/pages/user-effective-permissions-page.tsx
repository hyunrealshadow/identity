import {
  Alert,
  AlertDescription,
} from '@identity/ui/components/alert'
import { Badge } from '@identity/ui/components/badge'
import { Link, useNavigate } from '@tanstack/react-router'
import { TriangleAlert } from 'lucide-react'
import { useMemo } from 'react'

import { AsyncState } from '#/components/async-state'
import { CopyButton } from '#/components/copy-button'
import { CursorPagination } from '#/components/cursor-pagination'
import { CollectionToolbar, ResourceTable } from '#/components/resource-table'
import {
  ConsoleUserPermissionsDocument,
  type ConsoleUserPermissionsQuery,
  type ConsoleUserPermissionsQueryVariables,
} from '#/generated/graphql'
import {
  failureDescriptionKey,
  failureTitleKey,
} from '#/lib/graphql/presentation'
import { useLocale, useTranslator } from '#/lib/i18n'
import { useWorkspace } from '#/lib/workspace'
import { useCursorPagination } from '#/lib/use-cursor-pagination'
import { useAuthorizationLabels } from '#/modules/user-management/authorization/hooks/use-authorization-labels'
import { ApiResourceSelect } from '#/modules/user-management/components/api-resource-select'
import { ConsoleWorkspaceGate } from '#/modules/user-management/components/workspace-gate'
import { resolveLocalizedText } from '#/modules/user-management/groups/lib/groups-search'
import { RbacAccessRestricted } from '#/modules/user-management/roles/components/role-access'
import {
  sameVariable,
  useConsoleQuery,
} from '#/lib/graphql/use-console-query'
import { cursorPage } from '#/modules/user-management/lib/cursor-page'
import { rbacScope } from '#/modules/user-management/lib/rbac-scope'
import { FIRST_PAGE } from '#/modules/user-management/lib/relation-search'
import type { UserPermissionsSearch } from '#/modules/user-management/authorization/lib/user-authorization-search'
import { UserDetailTabSkeleton } from '#/modules/user-management/users/components/user-detail-skeleton'
import { useUserDetailContext } from '#/modules/user-management/users/components/user-detail-context'
import {
  AuthorizationSourceFilter,
  canFilterBySource,
  sourceVariable,
  type AuthorizationSourceFilterValue,
} from '#/modules/user-management/authorization/components/authorization-source-filter'

export function UserEffectivePermissionsPage({
  userId,
  listSearch,
}: {
  userId: string
  listSearch: UserPermissionsSearch
}) {
  const t = useTranslator()
  const { locale } = useLocale()
  const navigate = useNavigate()
  const workspace = useWorkspace()
  const scope = useMemo(
    () => rbacScope(workspace.data?.effectivePermissions),
    [workspace.data?.effectivePermissions],
  )
  const userDetail = useUserDetailContext()
  // Filters and paging live in the URL so a reload or link restores them.
  const { after, before } = listSearch
  const pageSize = listSearch.size ?? 100
  const resourceId = listSearch.resource ?? ''
  const go = (next: UserPermissionsSearch, replace = false) =>
    void navigate({
      to: '/users/$userId/permissions',
      params: { userId },
      search: next,
      replace,
    })
  const sourceFilterable = canFilterBySource(scope)
  const sourceFilter: AuthorizationSourceFilterValue = listSearch.source ?? 'any'
  const source = sourceFilterable ? sourceVariable(sourceFilter) : undefined
  // The automatic first choice replaces the entry, so Back leaves the page.
  const selectResource = (id: string, options?: { automatic: boolean }) =>
    go(
      { ...listSearch, resource: id || undefined, ...FIRST_PAGE },
      options?.automatic,
    )
  const variables = useMemo<ConsoleUserPermissionsQueryVariables | null>(
    () =>
      scope.usersRead && scope.assignmentsRead && resourceId
        ? {
            userId,
            resourceId,
            source,
            orderBy: 'CODE_ASC',
            ...cursorPage(pageSize, after, before),
          }
        : null,
    [
      userId,
      resourceId,
      source,
      scope.usersRead,
      scope.assignmentsRead,
      pageSize,
      after,
      before,
    ],
  )
  const permissions = useConsoleQuery<
    ConsoleUserPermissionsQuery,
    ConsoleUserPermissionsQueryVariables
  >(
    ConsoleUserPermissionsDocument,
    variables,
    Boolean(variables),
    'missing_effective_permissions',
    { keepPreviousData: sameVariable('userId') },
  )
  const connection = permissions.data?.user?.effectivePermissions
  const labelIds = useMemo(() => {
    const ids = new Set<string>()
    for (const { node } of connection?.edges ?? []) {
      if (scope.permissionRead) ids.add(node.permissionId)
      if (scope.rolesRead) {
        for (const source of [...node.sources, ...node.groupSources])
          ids.add(source.roleId)
      }
    }
    for (const { node } of connection?.edges ?? []) {
      if (scope.groupsRead)
        for (const source of node.groupSources) ids.add(source.groupId)
    }
    return [...ids]
  }, [connection, scope.permissionRead, scope.rolesRead, scope.groupsRead])
  const labels = useAuthorizationLabels(labelIds)
  const labelMap = new Map(labels.nodes.map((node) => [node.id, node]))
  const groupName = (id: string) => {
    const group = labelMap.get(id)
    return group?.__typename === 'Group'
      ? (resolveLocalizedText(group.names, locale) ?? group.name)
      : t('rbacGroupSource')
  }
  const roleName = (id: string) => {
    const role = labelMap.get(id)
    return role?.__typename === 'Role'
      ? (resolveLocalizedText(role.names, locale) ?? role.name)
      : t('rbacRoleSource')
  }
  const pagination = useCursorPagination({
    search: { after, before },
    variables,
    onNavigate: (cursor) =>
      go({ ...listSearch, after: cursor.after, before: cursor.before }),
  })
  const loadingView = (
    <UserDetailTabSkeleton userId={userId} tab="permissions" />
  )
  if (!scope.usersRead) {
    return (
      <>
        <ConsoleWorkspaceGate loading={loadingView}>
          <RbacAccessRestricted
            title="usersNoReadTitle"
            description="userAuthorizationUsersReadDescription"

            onBack={() => void navigate({ to: '/users' })}
            backLabel="backToUsers"
          />
        </ConsoleWorkspaceGate>
      </>
    )
  }

  if (!scope.assignmentsRead) {
    return (
      <>
        <ConsoleWorkspaceGate loading={loadingView}>
          <RbacAccessRestricted
            title="userPermissionsNoReadTitle"
            description="userPermissionsNoReadDescription"

            onBack={() =>
              void navigate({ to: '/users/$userId', params: { userId } })
            }
            backLabel="usersBackToDetail"
          />
        </ConsoleWorkspaceGate>
      </>
    )
  }

  if (userDetail.notFound) {
    return (
      <>
        <ConsoleWorkspaceGate loading={loadingView}>
          <AsyncState kind="notFound" title={t('notFoundTitle')} />
        </ConsoleWorkspaceGate>
      </>
    )
  }

  if (userDetail.status === 'error') {
    return (
      <>
        <ConsoleWorkspaceGate loading={loadingView}>
          <AsyncState
            kind={userDetail.forbidden ? 'forbidden' : 'error'}
            title={t(failureTitleKey(userDetail.failure, userDetail.forbidden))}
            description={t(
              failureDescriptionKey(userDetail.failure, userDetail.forbidden),
            )}
            requestId={userDetail.requestId}
            traceId={userDetail.traceId}
            issues={userDetail.errors}
            onRetry={() => void userDetail.refresh()}
          />
        </ConsoleWorkspaceGate>
      </>
    )
  }

  const filters = (
    <div className="flex flex-wrap items-start gap-2">
      <ApiResourceSelect
        value={resourceId}
        onChange={selectResource}
        enabled={scope.resourcesRead}
        hideLabel
      />
      {resourceId && sourceFilterable ? (
        <AuthorizationSourceFilter
          name="user-permission-source"
          value={sourceFilter}
          onChange={(value) => {
            go({ ...listSearch, source: value === 'any' ? undefined : value, ...FIRST_PAGE })
          }}
        />
      ) : null}
    </div>
  )
  const items = (connection?.edges ?? []).map(({ node }) => ({
    id: node.permissionId,
    ...node,
  }))
  return (
    <ConsoleWorkspaceGate loading={loadingView}>
      <section className="space-y-5">
        <p className="text-sm text-muted-foreground">{t('rbacUserPermissionsIntro')}</p>
        {resourceId ? null : <CollectionToolbar filters={filters} />}
        {!scope.resourcesRead ? (
          <AsyncState
            kind="forbidden"
            compact
            title={t('userPermissionsResourceLoadFailed')}
          />
        ) : null}
        {resourceId ? (
          <ResourceTable
            id="user-effective-permissions"
            filters={filters}
            density="compact"
            maxHeight="clamp(12rem, calc(100dvh - 34rem), 30rem)"
            label={t('userPermissionsTableLabel')}
            items={items}
            onOrderChange={() => undefined}
            onRefresh={() => void permissions.refresh()}
            refreshing={
              permissions.refreshing || permissions.status === 'loading'
            }
            emptyState={
              permissions.status === 'error' ? (
                <AsyncState
                  kind={permissions.forbidden ? 'forbidden' : 'error'}
                  title={t(
                    failureTitleKey(permissions.failure, permissions.forbidden),
                  )}
                  description={t(
                    failureDescriptionKey(
                      permissions.failure,
                      permissions.forbidden,
                    ),
                  )}
                  requestId={permissions.requestId}
                  traceId={permissions.traceId}
                  issues={permissions.errors}
                  onRetry={() => void permissions.refresh()}
                />
              ) : (
                <AsyncState
                  kind="empty"
                  compact
                  title={t(
                    source
                      ? 'userPermissionsEmptyFilteredTitle'
                      : 'userPermissionsEmptyTitle',
                  )}
                />
              )
            }
            pagination={
              connection ? (
                <CursorPagination
                  label={t('userPermissionsPagination')}
                  pageCount={connection.edges.length}
                  totalCount={connection.totalCount}
                  pageInfo={connection.pageInfo}
                  controller={pagination}
                  isDisabled={permissions.refreshing}
                  pageSize={pageSize}
                  onPageSizeChange={(size) =>
                    go({ ...listSearch, size, ...FIRST_PAGE })
                  }
                />
              ) : null
            }
            columns={[
              {
                id: 'permission',
                label: t('userPermissionsColumnPermission'),
                primary: true,
                render: (row) => {
                  const info = labelMap.get(row.id)
                  const name =
                    info?.__typename === 'Scope'
                      ? (resolveLocalizedText(info.names, locale) ?? info.name)
                      : undefined
                  return (
                    <div className="min-w-48">
                      <div className="flex items-center gap-1">
                        {scope.permissionRead ? (
                          <Link
                            to="/resources/$resourceId/permissions/$permissionId"
                            params={{
                              resourceId: row.resourceId,
                              permissionId: row.id,
                            }}
                            className="font-mono text-sm hover:underline"
                          >
                            {row.code}
                          </Link>
                        ) : (
                          <span className="font-mono text-sm">{row.code}</span>
                        )}
                        <CopyButton
                          value={row.code}
                          label={t('permissionCodeLabel')}
                        />
                      </div>
                      {name && name !== row.code ? (
                        <p className="mt-1 text-xs text-muted-foreground">{name}</p>
                      ) : null}
                    </div>
                  )
                },
              },
              {
                id: 'description',
                label: t('rbacPermissionDescription'),
                render: (row) => {
                  const info = labelMap.get(row.id)
                  return info?.__typename === 'Scope' ? (
                    <span className="text-sm text-muted-foreground">
                      {resolveLocalizedText(info.descriptions, locale) ??
                        info.description}
                    </span>
                  ) : null
                },
              },
              {
                id: 'sources',
                label: t('userPermissionsColumnSources'),
                render: (row) => (
                  <div className="flex max-w-xl flex-wrap gap-2">
                    {row.sources.map((source) => (
                      <Badge key={source.roleId} variant="secondary">
                        {scope.rolesRead ? (
                          <Link
                            to="/roles/$roleId"
                            params={{ roleId: source.roleId }}
                            className="hover:underline"
                          >
                            {roleName(source.roleId)}
                          </Link>
                        ) : (
                          t('rbacRoleSource')
                        )}
                      </Badge>
                    ))}
                    {row.groupSources.map((source) => (
                      <Badge
                        key={`${source.groupId}/${source.roleId}`}
                        variant="secondary"
                      >
                        {scope.groupsRead ? (
                          <Link
                            to="/groups/$groupId"
                            params={{ groupId: source.groupId }}
                            className="hover:underline"
                          >
                            {groupName(source.groupId)}
                          </Link>
                        ) : (
                          t('rbacGroupSource')
                        )}
                        <span className="mx-1 text-muted-foreground">/</span>
                        {scope.rolesRead ? (
                          <Link
                            to="/roles/$roleId"
                            params={{ roleId: source.roleId }}
                            className="hover:underline"
                          >
                            {roleName(source.roleId)}
                          </Link>
                        ) : (
                          t('rbacRoleSource')
                        )}
                      </Badge>
                    ))}
                  </div>
                ),
              },
            ]}
          />
        ) : null}
        {labels.failed ? (
          <Alert variant="default" className="text-warning">
            <TriangleAlert aria-hidden="true" />
            <AlertDescription>
              {t('rbacLabelsUnavailable')}
            </AlertDescription>
          </Alert>
        ) : null}
      </section>
    </ConsoleWorkspaceGate>
  )
}
