import { AssignRolesDialog } from '../../roles/components/assign-user-roles-dialog'
import { RelationPagination } from '../../components/relation-picker'

import { RevokeUserRoleDialog } from '../../roles/components/revoke-user-role-dialog'

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
} from '#/generated/graphql'
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
import { AssignmentStatusChip } from '#/modules/user-management/roles/components/role-status'

import { useConsoleQuery } from '#/lib/graphql/use-console-query'
import { cursorPage } from '#/modules/user-management/lib/cursor-page'

import { rbacScope } from '#/modules/user-management/lib/rbac-scope'
import { useUserDetailContext } from '#/modules/user-management/users/components/user-detail-context'
import { UserSelectField } from '#/modules/user-management/users/components/user-form-fields'

type AssignmentStatus = 'any' | 'active' | 'revoked'

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
  const [status, setStatus] = useState<AssignmentStatus>('active')
  const [after, setAfter] = useState<string | undefined>()
  const [before, setBefore] = useState<string | undefined>()
  const [notice, setNotice] = useState<RbacNotice | null>(null)
  const variables = useMemo<ConsoleUserRolesQueryVariables | null>(
    () =>
      scope.usersRead && scope.assignmentsRead && scope.rolesRead
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
  const assignments = useConsoleQuery<
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
  const connection = assignments.data?.user?.roles ?? null

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

  if (!scope.rolesRead) {
    return (
      <>
        <ConsoleWorkspaceGate loading={loadingView}>
          <RbacAccessRestricted
            title="rolesNoReadTitle"
            description="rolesNoReadDescription"
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

          {assignments.stepUp ? (
            <StepUpPanel
              stepUp={assignments.stepUp}
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
                      { id: 'any', label: t('assignmentFilterAll') },
                      { id: 'active', label: t('assignmentFilterActive') },
                      { id: 'revoked', label: t('assignmentFilterRevoked') },
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
                    }}
                    onReload={() => void assignments.refresh()}
                    reloadPending={assignments.refreshing}
                  />
                ) : scope.assignmentsWrite && scope.rolesRead ? (
                  <UserDetailActionSkeleton
                    label={t('userRolesAssignAction')}
                    icon={<ShieldPlus className="size-4" />}
                  />
                ) : null}
              </div>
            </header>
            <div className="min-w-0">{renderAssignments()}</div>
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
                    assignments.refreshing || assignments.status !== 'ready'
                  }
                />
              ) : assignments.status === 'idle' ||
                assignments.status === 'loading' ? (
                <UserDetailPaginationSkeleton />
              ) : null}
            </footer>
          </section>
        </div>
      </ConsoleWorkspaceGate>
    </>
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
      return <UserDetailTableSkeleton label={t('userRolesLoading')} />
    }
    const edges = connection?.edges ?? []
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
        {assignments.partial ? (
          <div className="p-3">
            <Alert status="warning">
              <Alert.Indicator />
              <Alert.Content>
                <Alert.Title>{t('rolesPartialTitle')}</Alert.Title>
                <Alert.Description>
                  {t('rolesPartialDescription')}
                </Alert.Description>
                <RequestCorrelation
                  requestId={assignments.requestId}
                  traceId={assignments.traceId}
                />
                <ErrorDetails issues={assignments.errors} />
              </Alert.Content>
            </Alert>
          </div>
        ) : null}
        <DataTable
          loading={assignments.refreshing}
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
            {edges.map((edge) => {
              const role = edge.node
              const roleName =
                resolveLocalizedText(role.names, locale) ?? role.name
              return (
                <DataTable.Row key={role.id} id={role.id}>
                  <DataTable.Cell>
                    <div className="min-w-48">
                      <p className="font-medium">{roleName}</p>
                      {!role.enabled ? (
                        <p className="mt-1 text-xs text-warning">
                          {t('assignmentRoleDisabledHint')}
                        </p>
                      ) : null}
                    </div>
                  </DataTable.Cell>
                  <DataTable.Cell>
                    <AssignmentStatusChip
                      enabled={edge.enabled}
                      revokedAt={edge.revokedAt}
                      roleEnabled={role.enabled}
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
                        <RevokeUserRoleDialog
                          assignment={{
                            userId,
                            roleId: role.id,
                            userVersion: connection?.userVersion,
                          }}
                          label={roleName}
                          onRevoked={() => {
                            setNotice({
                              kind: 'success',
                              title: t('userRolesRevokedTitle'),
                              description: t('userRolesRevokedDescription'),
                            })
                          }}
                          onReload={() => void assignments.refresh()}
                          reloadPending={assignments.refreshing}
                        />
                      ) : (
                        <span className="text-xs text-muted">
                          {t('userRolesNoWritePermission')}
                        </span>
                      )
                    ) : (
                      <span className="text-xs text-muted">
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
