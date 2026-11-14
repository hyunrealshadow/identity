import { AssignUserDialog } from '../components/assign-role-user-dialog'
import { useRoleDetailContext } from '../components/role-detail-context'
import { RelationPagination } from '../../components/relation-picker'

import { RevokeRoleFromUserDialog } from '../components/revoke-user-role-dialog'

import { DataTable } from '@identity/ui/data-table'
import { Alert, AlertDescription, AlertTitle } from '@identity/ui/components/alert'
import { Skeleton } from '@identity/ui/components/skeleton'
import { Link, useNavigate } from '@tanstack/react-router'
import { TriangleAlert } from 'lucide-react'

import { useMemo, useState } from 'react'

import { AsyncState } from '#/components/async-state'
import { CollectionToolbar } from '#/components/resource-table'
import { ErrorDetails } from '#/components/error-details'
import { RequestCorrelation } from '#/components/request-correlation'

import {
  ConsoleRoleUsersDocument,
  type ConsoleRoleUsersQuery,
  type ConsoleRoleUsersQueryVariables,
} from '#/generated/graphql'
import {
  failureDescriptionKey,
  failureTitleKey,
} from '#/lib/graphql/presentation'
import { formatDateTime } from '#/lib/format'
import { useLocale, useTranslator } from '#/lib/i18n'

import { useWorkspace } from '#/lib/workspace'
import {
  type RbacNotice,
  RbacNoticeAlert,
} from '#/modules/user-management/components/rbac-feedback'
import { ConsoleWorkspaceGate } from '#/modules/user-management/components/workspace-gate'
import { RbacAccessRestricted } from '#/modules/user-management/roles/components/role-access'
import { AssignmentStatusChip } from '#/modules/user-management/roles/components/role-status'

import {
  sameVariable,
  useConsoleQuery,
} from '#/lib/graphql/use-console-query'
import { cursorPage } from '#/modules/user-management/lib/cursor-page'

import { rbacScope } from '#/modules/user-management/lib/rbac-scope'
import { FIRST_PAGE } from '#/modules/user-management/lib/relation-search'
import type { RoleUsersSearch } from '#/modules/user-management/roles/lib/role-users-search'
import { UserSelectField } from '#/modules/user-management/users/components/user-form-fields'

type UserStatus = 'any' | 'active' | 'revoked'


export function RoleUsersPage({
  roleId,
  listSearch,
}: {
  roleId: string
  listSearch: RoleUsersSearch
}) {
  const t = useTranslator()
  const { locale, timeZone } = useLocale()
  const navigate = useNavigate()
  const workspace = useWorkspace()
  const scope = useMemo(
    () => rbacScope(workspace.data?.effectivePermissions),
    [workspace.data?.effectivePermissions],
  )
  const roleQuery = useRoleDetailContext()
  const status: UserStatus = listSearch.status ?? 'any'
  // Filters and paging live in the URL so a reload or link restores them.
  const { after, before } = listSearch
  const pageSize = listSearch.size ?? 10
  const go = (next: RoleUsersSearch, replace = false) =>
    void navigate({
      to: '/roles/$roleId/users',
      params: { roleId },
      search: next,
      replace,
    })
  const [notice, setNotice] = useState<RbacNotice | null>(null)
  const assignmentsVariables = useMemo<ConsoleRoleUsersQueryVariables | null>(
    () =>
      scope.rolesRead && scope.assignmentsRead && scope.usersRead
        ? {
            roleId,
            enabled:
              status === 'active'
                ? true
                : status === 'revoked'
                  ? false
                  : undefined,
            orderBy: 'CREATED_AT_DESC',
            ...cursorPage(pageSize, after, before),
          }
        : null,
    [
      after,
      before,
      roleId,
      scope.assignmentsRead,
      scope.rolesRead,
      scope.usersRead,
      status,
      pageSize,
    ],
  )
  const assignments = useConsoleQuery<
    ConsoleRoleUsersQuery,
    ConsoleRoleUsersQueryVariables
  >(
    ConsoleRoleUsersDocument,
    assignmentsVariables,
    Boolean(assignmentsVariables),
    'missing_role_users',
    { keepPreviousData: sameVariable('roleId') },
  )
  const role = roleQuery.data?.role ?? null

  if (!scope.rolesRead || !scope.assignmentsRead || !scope.usersRead) {
    return (
      <ConsoleWorkspaceGate>
        <RbacAccessRestricted
          title={
            !scope.rolesRead
              ? 'rolesNoReadTitle'
              : !scope.usersRead
                ? 'usersNoReadTitle'
                : 'roleUsersNoReadTitle'
          }
          description={
            !scope.rolesRead
              ? 'rolesNoReadDescription'
              : !scope.usersRead
                ? 'userAuthorizationUsersReadDescription'
                : 'roleUsersNoReadDescription'
          }

          onBack={() => void navigate({ to: '/roles' })}
          backLabel="backToRoles"
        />
      </ConsoleWorkspaceGate>
    )
  }

  if (roleQuery.status === 'error') {
    return (
      <ConsoleWorkspaceGate>
        <AsyncState
          kind={roleQuery.forbidden ? 'forbidden' : 'error'}
          title={t(failureTitleKey(roleQuery.failure, roleQuery.forbidden))}
          description={t(
            failureDescriptionKey(roleQuery.failure, roleQuery.forbidden),
          )}
          requestId={roleQuery.requestId}
          traceId={roleQuery.traceId}
          issues={roleQuery.errors}
          onRetry={() => void roleQuery.refresh()}
        />
      </ConsoleWorkspaceGate>
    )
  }

  if (roleQuery.status === 'ready' && !role) {
    return (
      <ConsoleWorkspaceGate>
        <AsyncState kind="notFound" title={t('notFoundTitle')} />
      </ConsoleWorkspaceGate>
    )
  }

  if (roleQuery.status !== 'ready' || !role) {
    return (
      <ConsoleWorkspaceGate>
        <AsyncState kind="loading" title={t('loading')} />
      </ConsoleWorkspaceGate>
    )
  }

  const roleReady = role

  return (
    <ConsoleWorkspaceGate>
      <div className="space-y-4">
        {notice ? (
          <RbacNoticeAlert notice={notice} onDismiss={() => setNotice(null)} />
        ) : null}

        <section className="space-y-4">
          <header className="flex flex-col gap-3 py-2 sm:flex-row sm:items-center sm:justify-between">
            <div>
              <h2 className="text-base font-semibold">
                {t('roleUsersListTitle')}
              </h2>
              <p className="mt-1 text-sm text-muted-foreground">
                {t('roleUsersListDescription')}
              </p>
            </div>
            <div className="flex shrink-0 items-center gap-2">
              {scope.assignmentsWrite && scope.usersRead ? (
                <AssignUserDialog
                  role={roleReady}
                  onAssigned={() => {
                    setNotice({
                      kind: 'success',
                      title: t('roleUserAssignedTitle'),
                      description: t('roleUserAssignedDescription'),
                    })
                    void assignments.refresh()
                  }}
                  onReload={() => void assignments.refresh()}
                  reloadPending={assignments.refreshing}
                />
              ) : null}
            </div>
          </header>
          <CollectionToolbar
            filters={
              <div className="flex flex-wrap items-start gap-2">
                <div className="w-36">
                  <UserSelectField
                    name="role-user-status"
                    label={t('rolesFilterStatusLabel')}
                    hideLabel
                    value={status}
                    onChange={(value) => {
                      if (
                        value === 'any' ||
                        value === 'active' ||
                        value === 'revoked'
                      ) {
                        go({ ...listSearch, status: value === 'any' ? undefined : value, ...FIRST_PAGE })
                      }
                    }}
                    options={[
                      { id: 'any', label: t('assignmentFilterAll') },
                      { id: 'active', label: t('assignmentFilterActive') },
                      { id: 'revoked', label: t('assignmentFilterRevoked') },
                    ]}
                  />
                </div>
              </div>
            }
          />
          <div className="p-0">{renderAssignments()}</div>
          <footer className="resource-collection-pagination">
            <RelationPagination
              connection={assignments.data?.role?.users ?? null}
              variables={assignmentsVariables}
              after={after}
              before={before}
              onNavigate={(page) =>
                go({ ...listSearch, after: page.after, before: page.before })
              }
              label={t('roleUsersPagination')}
              isDisabled={assignments.refreshing || assignments.status !== 'ready'}
              pageSize={pageSize}
              onPageSizeChange={(size) =>
                go({ ...listSearch, size, ...FIRST_PAGE })
              }
            />
          </footer>
        </section>
      </div>
    </ConsoleWorkspaceGate>
  )

  function renderAssignments() {
    if (assignments.status === 'error') {
      return (
        <div className="p-4">
          <AsyncState
            kind={assignments.forbidden ? 'forbidden' : 'error'}
            title={t(failureTitleKey(assignments.failure, assignments.forbidden))}
            description={t(
              failureDescriptionKey(assignments.failure, assignments.forbidden),
            )}
            requestId={assignments.requestId}
            traceId={assignments.traceId}
            issues={assignments.errors}
            onRetry={() => void assignments.refresh()}
          />
        </div>
      )
    }
    if (assignments.status !== 'ready' || !assignments.data) {
      return (
        <div
          className="space-y-2 p-4"
          role="status"
          aria-label={t('roleUsersLoading')}
        >
          <span className="sr-only">{t('roleUsersLoading')}</span>
          {Array.from({ length: 4 }, (_, index) => (
            <Skeleton key={index} className="h-12 w-full rounded-lg" />
          ))}
        </div>
      )
    }
    const edges = assignments.data.role?.users.edges ?? []
    return (
      <div>
        {assignments.partial ? (
          <div className="p-3">
            <Alert variant="default" className="text-warning">
              <TriangleAlert aria-hidden="true" />
              <AlertTitle>{t('rolesPartialTitle')}</AlertTitle>
              <AlertDescription>
                {t('rolesPartialDescription')}
              </AlertDescription>
              <RequestCorrelation
                requestId={assignments.requestId}
                traceId={assignments.traceId}
              />
              <ErrorDetails issues={assignments.errors} />
            </Alert>
          </div>
        ) : null}
        <DataTable
          label={t('roleUsersTableLabel')}
          minWidth={820}
          columns={[
            {
              id: 'roleUsersColumnUser',
              label: t('roleUsersColumnUser'),
              primary: true,
            },
            {
              id: 'roleUsersColumnStatus',
              label: t('roleUsersColumnStatus'),
              primary: false,
            },
            {
              id: 'roleUsersColumnCreated',
              label: t('roleUsersColumnCreated'),
              primary: false,
            },
            {
              id: 'roleUsersColumnActions',
              label: t('roleUsersColumnActions'),
              primary: false,
            },
          ]}
        >
          <DataTable.Body
            renderEmptyState={() => (
              <AsyncState
                kind="empty"
                compact
                title={t('roleUsersEmptyTitle')}
                description={
                  status === 'any'
                    ? t('roleUsersEmptyDescription')
                    : t('roleUsersEmptyFilteredDescription')
                }
              />
            )}
          >
            {edges.map((edge) => {
              const user = edge.node
              return (
                <DataTable.Row key={user.id} id={user.id}>
                  <DataTable.Cell>
                    <div className="min-w-48">
                      <Link
                        to="/users/$userId"
                        params={{ userId: user.id }}
                        className="font-medium text-foreground underline-offset-4 hover:underline"
                      >
                        {user.username}
                      </Link>
                      {user.email ? (
                        <p className="mt-0.5 break-all text-xs text-muted-foreground">
                          {user.email}
                        </p>
                      ) : null}
                    </div>
                  </DataTable.Cell>
                  <DataTable.Cell>
                    <AssignmentStatusChip
                      enabled={edge.enabled}
                      revokedAt={edge.revokedAt}
                    />
                  </DataTable.Cell>
                  <DataTable.Cell>
                    <span className="whitespace-nowrap text-sm">
                      {formatDateTime(edge.createdAt, locale, timeZone)}
                    </span>
                  </DataTable.Cell>
                  <DataTable.Cell>
                    {edge.enabled ? (
                      scope.assignmentsWrite ? (
                        <RevokeRoleFromUserDialog
                          assignment={{
                            userId: user.id,
                            roleId,
                            userVersion: user.version,
                          }}
                          label={user.username}
                          onRevoked={() => {
                            setNotice({
                              kind: 'success',
                              title: t('roleUserRevokedTitle'),
                              description: t('roleUserRevokedDescription'),
                            })
                            void assignments.refresh()
                          }}
                          onReload={() => void assignments.refresh()}
                          reloadPending={assignments.refreshing}
                        />
                      ) : (
                        <span className="text-xs text-muted-foreground">
                          {t('roleUsersNoWritePermission')}
                        </span>
                      )
                    ) : (
                      <span className="text-xs text-muted-foreground">
                        {formatDateTime(edge.revokedAt, locale, timeZone)}
                      </span>
                    )}
                  </DataTable.Cell>
                </DataTable.Row>
              )
            })}
          </DataTable.Body>
        </DataTable>
      </div>
    )
  }
}
