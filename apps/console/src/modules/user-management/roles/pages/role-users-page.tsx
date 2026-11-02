import { AssignUserDialog } from '../components/assign-role-user-dialog'
import { useRoleDetailContext } from '../components/role-detail-context'
import { RelationPagination } from '../../components/relation-picker'

import { RevokeRoleFromUserDialog } from '../components/revoke-user-role-dialog'

import { DataTable } from '@identity/ui/data-table'
import { Alert, Skeleton } from '@heroui/react'
import { Link, useNavigate } from '@tanstack/react-router'

import { useMemo, useState } from 'react'

import { AsyncState } from '#/components/async-state'
import { ErrorDetails } from '#/components/error-details'
import { RequestCorrelation } from '#/components/request-correlation'

import {
  ConsoleRoleUsersDocument,
  type ConsoleRoleUsersQuery,
  type ConsoleRoleUsersQueryVariables,
} from '#/gql/graphql'
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
import { BindingStatusChip } from '#/modules/user-management/roles/components/role-status'

import { useConsoleQuery } from '#/modules/user-management/lib/console-query'
import { cursorPage } from '#/modules/user-management/lib/cursor-page'

import { rbacScope } from '#/modules/user-management/lib/rbac-scope'
import { UserSelectField } from '#/modules/user-management/users/components/user-form-fields'

type UserStatus = 'any' | 'active' | 'revoked'

const PAGE_SIZE = 10

export function RoleUsersPage({ roleId }: { roleId: string }) {
  const t = useTranslator()
  const { locale, timeZone } = useLocale()
  const navigate = useNavigate()
  const workspace = useWorkspace()
  const scope = useMemo(
    () => rbacScope(workspace.data?.effectivePermissions),
    [workspace.data?.effectivePermissions],
  )
  const roleQuery = useRoleDetailContext()
  const [status, setStatus] = useState<UserStatus>('any')
  const [after, setAfter] = useState<string | undefined>()
  const [before, setBefore] = useState<string | undefined>()
  const [notice, setNotice] = useState<RbacNotice | null>(null)
  const bindingsVariables = useMemo<ConsoleRoleUsersQueryVariables | null>(
    () =>
      scope.rolesRead && scope.assignmentsRead
        ? {
            roleId,
            enabled:
              status === 'active'
                ? true
                : status === 'revoked'
                  ? false
                  : undefined,
            orderBy: 'CREATED_AT_DESC',
            ...cursorPage(PAGE_SIZE, after, before),
            includeUser: scope.usersRead,
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
    ],
  )
  const bindings = useConsoleQuery<
    ConsoleRoleUsersQuery,
    ConsoleRoleUsersQueryVariables
  >(
    ConsoleRoleUsersDocument,
    bindingsVariables,
    'ConsoleRoleUsers',
    Boolean(bindingsVariables),
    'missing_role_users',
  )
  const role = roleQuery.data?.role ?? null

  if (!scope.rolesRead || !scope.assignmentsRead) {
    return (
      <ConsoleWorkspaceGate>
        <RbacAccessRestricted
          title={!scope.rolesRead ? 'rolesNoReadTitle' : 'roleUsersNoReadTitle'}
          description={
            !scope.rolesRead
              ? 'rolesNoReadDescription'
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
              <p className="mt-1 text-sm text-muted">
                {t('roleUsersListDescription')}
              </p>
            </div>
            <div className="flex items-center gap-2">
              <div className="w-40">
                <UserSelectField
                  name="role-user-status"
                  label={t('rolesFilterStatusLabel')}
                  value={status}
                  onChange={(value) => {
                    if (
                      value === 'any' ||
                      value === 'active' ||
                      value === 'revoked'
                    ) {
                      setStatus(value)
                      setAfter(undefined)
                      setBefore(undefined)
                    }
                  }}
                  options={[
                    { id: 'any', label: t('bindingFilterAll') },
                    { id: 'active', label: t('bindingFilterActive') },
                    { id: 'revoked', label: t('bindingFilterRevoked') },
                  ]}
                />
              </div>
              {scope.assignmentsWrite && scope.usersRead ? (
                <AssignUserDialog
                  role={roleReady}
                  onAssigned={() => {
                    setNotice({
                      kind: 'success',
                      title: t('roleUserAssignedTitle'),
                      description: t('roleUserAssignedDescription'),
                    })
                    void bindings.refresh()
                  }}
                  onReload={() => void bindings.refresh()}
                  reloadPending={bindings.refreshing}
                />
              ) : null}
            </div>
          </header>
          <div className="p-0">{renderBindings()}</div>
          <footer className="border-t border-separator pt-4">
            <RelationPagination
              connection={bindings.data?.roleUsers ?? null}
              variables={bindingsVariables}
              after={after}
              before={before}
              onNavigate={(page) => {
                setAfter(page.after)
                setBefore(page.before)
              }}
              label={t('roleUsersPagination')}
              isDisabled={bindings.refreshing || bindings.status !== 'ready'}
            />
          </footer>
        </section>
      </div>
    </ConsoleWorkspaceGate>
  )

  function renderBindings() {
    if (bindings.status === 'error') {
      return (
        <div className="p-4">
          <AsyncState
            kind={bindings.forbidden ? 'forbidden' : 'error'}
            title={t(failureTitleKey(bindings.failure, bindings.forbidden))}
            description={t(
              failureDescriptionKey(bindings.failure, bindings.forbidden),
            )}
            requestId={bindings.requestId}
            traceId={bindings.traceId}
            issues={bindings.errors}
            onRetry={() => void bindings.refresh()}
          />
        </div>
      )
    }
    if (bindings.status !== 'ready' || !bindings.data) {
      return (
        <div
          className="space-y-2 p-4"
          role="status"
          aria-label={t('roleUsersLoading')}
        >
          <span className="sr-only">{t('roleUsersLoading')}</span>
          {Array.from({ length: 4 }, (_, index) => (
            <Skeleton key={index} className="h-12 w-full rounded-field" />
          ))}
        </div>
      )
    }
    const edges = bindings.data.roleUsers.edges
    if (edges.length === 0) {
      return (
        <div className="p-4">
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
        </div>
      )
    }
    return (
      <div>
        {bindings.partial ? (
          <div className="p-3">
            <Alert status="warning">
              <Alert.Indicator />
              <Alert.Content>
                <Alert.Title>{t('rolesPartialTitle')}</Alert.Title>
                <Alert.Description>
                  {t('rolesPartialDescription')}
                </Alert.Description>
                <RequestCorrelation
                  requestId={bindings.requestId}
                  traceId={bindings.traceId}
                />
                <ErrorDetails issues={bindings.errors} />
              </Alert.Content>
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
          <DataTable.Body>
            {edges.map(({ node }) => (
              <DataTable.Row key={node.id} id={node.id}>
                <DataTable.Cell>
                  <div className="min-w-48">
                    {node.user && scope.usersRead ? (
                      <Link
                        to="/users/$userId"
                        params={{ userId: node.user.id }}
                        className="font-medium text-foreground underline-offset-4 hover:underline"
                      >
                        {node.user.username}
                      </Link>
                    ) : node.user ? (
                      <span className="font-medium">{node.user.username}</span>
                    ) : (
                      <span className="font-mono text-xs">{node.userId}</span>
                    )}
                    {node.user?.email ? (
                      <p className="mt-0.5 break-all text-xs text-muted">
                        {node.user.email}
                      </p>
                    ) : null}
                  </div>
                </DataTable.Cell>
                <DataTable.Cell>
                  <BindingStatusChip
                    enabled={node.enabled}
                    revokedAt={node.revokedAt}
                  />
                </DataTable.Cell>
                <DataTable.Cell>
                  <span className="whitespace-nowrap text-sm">
                    {formatDateTime(node.createdAt, locale, timeZone)}
                  </span>
                </DataTable.Cell>
                <DataTable.Cell>
                  {node.enabled ? (
                    scope.assignmentsWrite ? (
                      <RevokeRoleFromUserDialog
                        binding={node}
                        onRevoked={() => {
                          setNotice({
                            kind: 'success',
                            title: t('roleUserRevokedTitle'),
                            description: t('roleUserRevokedDescription'),
                          })
                          void bindings.refresh()
                        }}
                        onReload={() => void bindings.refresh()}
                        reloadPending={bindings.refreshing}
                      />
                    ) : (
                      <span className="text-xs text-muted">
                        {t('roleUsersNoWritePermission')}
                      </span>
                    )
                  ) : (
                    <span className="text-xs text-muted">
                      {formatDateTime(node.revokedAt, locale, timeZone)}
                    </span>
                  )}
                </DataTable.Cell>
              </DataTable.Row>
            ))}
          </DataTable.Body>
        </DataTable>
      </div>
    )
  }
}
