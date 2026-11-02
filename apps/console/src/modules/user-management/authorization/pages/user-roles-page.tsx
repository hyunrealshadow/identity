import { AssignRolesDialog } from '../../roles/components/assign-user-roles-dialog'
import { RelationPagination } from '../../components/relation-picker'

import { RevokeBindingDialog } from '../../roles/components/revoke-user-role-dialog'

import { DataTable } from '@identity/ui/data-table'
import { Alert } from '@heroui/react'
import { useNavigate } from '@tanstack/react-router'
import { ShieldPlus } from 'lucide-react'
import { useMemo, useState } from 'react'

import { AsyncState } from '#/components/async-state'
import { ErrorDetails } from '#/components/error-details'
import { RequestCorrelation } from '#/components/request-correlation'
import { StepUpPanel } from '#/components/step-up-panel'
import {
  ConsoleUserRolesDocument,
  type ConsoleUserRolesQuery,
  type ConsoleUserRolesQueryVariables,
} from '#/gql/graphql'
import {
  failureDescriptionKey,
  failureTitleKey,
} from '#/lib/graphql/presentation'
import { formatDateTime } from '#/lib/format'
import { useLocale, useTranslator } from '#/lib/i18n'
import { useWorkspace } from '#/lib/workspace'
import {
  UserDetailTabSkeleton,
  UserDetailTableSkeleton,
  UserDetailPaginationSkeleton,
  UserDetailActionSkeleton,
} from '#/modules/user-management/users/components/user-detail-skeleton'
import {
  RbacNoticeAlert,
  type RbacNotice,
} from '#/modules/user-management/components/rbac-feedback'
import { ConsoleWorkspaceGate } from '#/modules/user-management/components/workspace-gate'
import { resolveLocalizedText } from '#/modules/user-management/groups/lib/groups-search'
import { RbacAccessRestricted } from '#/modules/user-management/roles/components/role-access'
import { BindingStatusChip } from '#/modules/user-management/roles/components/role-status'

import { useConsoleQuery } from '#/modules/user-management/lib/console-query'
import { cursorPage } from '#/modules/user-management/lib/cursor-page'

import { rbacScope } from '#/modules/user-management/lib/rbac-scope'
import { useUserDetailContext } from '#/modules/user-management/users/components/user-detail-context'
import { UserSelectField } from '#/modules/user-management/users/components/user-form-fields'

type BindingStatus = 'any' | 'active' | 'revoked'

const PAGE_SIZE = 10

export function UserRolesPage({ userId }: { userId: string }) {
  const t = useTranslator()
  const { locale, timeZone } = useLocale()
  const navigate = useNavigate()
  const workspace = useWorkspace()
  const scope = useMemo(
    () => rbacScope(workspace.data?.effectivePermissions),
    [workspace.data?.effectivePermissions],
  )
  const userDetail = useUserDetailContext()
  const [status, setStatus] = useState<BindingStatus>('active')
  const [after, setAfter] = useState<string | undefined>()
  const [before, setBefore] = useState<string | undefined>()
  const [notice, setNotice] = useState<RbacNotice | null>(null)
  const variables = useMemo<ConsoleUserRolesQueryVariables | null>(
    () =>
      scope.usersRead && scope.assignmentsRead
        ? {
            userId,
            enabled:
              status === 'active'
                ? true
                : status === 'revoked'
                  ? false
                  : undefined,
            orderBy: 'CREATED_AT_DESC',
            ...cursorPage(PAGE_SIZE, after, before),
            includeRole: scope.rolesRead,
          }
        : null,
    [
      after,
      before,
      scope.assignmentsRead,
      scope.rolesRead,
      scope.usersRead,
      status,
      userId,
    ],
  )
  const bindings = useConsoleQuery<
    ConsoleUserRolesQuery,
    ConsoleUserRolesQueryVariables
  >(
    ConsoleUserRolesDocument,
    variables,
    'ConsoleUserRoles',
    Boolean(variables),
    'missing_user_roles',
  )
  const user = userDetail.user
  const connection = bindings.data?.userRoles ?? null

  const loadingView = <UserDetailTabSkeleton userId={userId} tab="roles" />

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
            title="userRolesNoReadTitle"
            description="userRolesNoReadDescription"

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

  const readyUser = user

  return (
    <>
      <ConsoleWorkspaceGate loading={loadingView}>
        <div className="space-y-4">
          {notice ? (
            <RbacNoticeAlert
              notice={notice}
              onDismiss={() => setNotice(null)}
            />
          ) : null}

          {bindings.stepUp ? (
            <StepUpPanel
              stepUp={bindings.stepUp}
              hideDetails
              description={t('rbacStepUpDescription')}
              note={t('rbacStepUpNote')}
            />
          ) : null}

          <section className="space-y-4">
            <header className="flex flex-col gap-3 py-2 sm:flex-row sm:items-center sm:justify-between">
              <div>
                <h2 className="text-base font-semibold">
                  {t('userRolesListTitle')}
                </h2>
                <p className="mt-1 text-sm text-muted">
                  {t('userRolesListDescription')}
                </p>
              </div>
              <div className="flex items-center gap-2">
                <div className="w-40">
                  <UserSelectField
                    name="user-role-status"
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
                {readyUser &&
                scope.assignmentsWrite &&
                scope.rolesRead &&
                connection ? (
                  <AssignRolesDialog
                    userId={readyUser.id}
                    username={readyUser.username}
                    expectedUserVersion={connection.userVersion ?? ''}
                    onAssigned={() => {
                      setNotice({
                        kind: 'success',
                        title: t('userRolesAssignedTitle'),
                        description: t('userRolesAssignedDescription'),
                      })
                      void bindings.refresh()
                    }}
                    onReload={() => void bindings.refresh()}
                    reloadPending={bindings.refreshing}
                  />
                ) : scope.assignmentsWrite && scope.rolesRead ? (
                  <UserDetailActionSkeleton
                    label={t('userRolesAssignAction')}
                    icon={<ShieldPlus className="size-4" />}
                  />
                ) : null}
              </div>
            </header>
            <div className="min-w-0">{renderBindings()}</div>
            <footer className="border-t border-separator pt-4">
              {connection ? (
                <RelationPagination
                  connection={connection}
                  variables={variables}
                  after={after}
                  before={before}
                  onNavigate={(page) => {
                    setAfter(page.after)
                    setBefore(page.before)
                  }}
                  label={t('userRolesPagination')}
                  isDisabled={
                    bindings.refreshing || bindings.status !== 'ready'
                  }
                />
              ) : bindings.status === 'idle' ||
                bindings.status === 'loading' ? (
                <UserDetailPaginationSkeleton />
              ) : null}
            </footer>
          </section>
        </div>
      </ConsoleWorkspaceGate>
    </>
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
      return <UserDetailTableSkeleton label={t('userRolesLoading')} />
    }
    const edges = bindings.data.userRoles.edges
    if (edges.length === 0) {
      return (
        <div className="p-4">
          <AsyncState
            kind="empty"
            compact
            title={t('userRolesEmptyTitle')}
            description={
              status !== 'revoked'
                ? t('userRolesEmptyDescription')
                : t('userRolesEmptyFilteredDescription')
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
          loading={bindings.refreshing}
          loadingLabel={t('tableLoading')}
          label={t('userRolesTableLabel')}
          minWidth={820}
          columns={[
            {
              id: 'userRolesColumnRole',
              label: t('userRolesColumnRole'),
              primary: true,
            },
            {
              id: 'userRolesColumnStatus',
              label: t('userRolesColumnStatus'),
              primary: false,
            },
            {
              id: 'userRolesColumnCreated',
              label: t('userRolesColumnCreated'),
              primary: false,
            },
            {
              id: 'userRolesColumnActions',
              label: t('userRolesColumnActions'),
              primary: false,
            },
          ]}
        >
          <DataTable.Body>
            {edges.map(({ node }) => (
              <DataTable.Row key={node.id} id={node.id}>
                <DataTable.Cell>
                  <div className="min-w-48">
                    <p className="font-medium">
                      {node.role
                        ? (resolveLocalizedText(node.role.names, locale) ??
                          node.role.name ??
                          node.role.id)
                        : node.roleId}
                    </p>
                    {node.role && !node.role.enabled ? (
                      <p className="mt-1 text-xs text-warning">
                        {t('bindingRoleDisabledHint')}
                      </p>
                    ) : null}
                  </div>
                </DataTable.Cell>
                <DataTable.Cell>
                  <BindingStatusChip
                    enabled={node.enabled}
                    revokedAt={node.revokedAt}
                    roleEnabled={node.role?.enabled}
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
                      <RevokeBindingDialog
                        binding={node}
                        onRevoked={() => {
                          setNotice({
                            kind: 'success',
                            title: t('userRolesRevokedTitle'),
                            description: t('userRolesRevokedDescription'),
                          })
                          void bindings.refresh()
                        }}
                        onReload={() => void bindings.refresh()}
                        reloadPending={bindings.refreshing}
                      />
                    ) : (
                      <span className="text-xs text-muted">
                        {t('userRolesNoWritePermission')}
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
