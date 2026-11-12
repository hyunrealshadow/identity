import { AssignRolesDialog } from '../../roles/components/assign-user-roles-dialog'
import { RelationPagination } from '../../components/relation-picker'

import { RevokeUserRoleDialog } from '../../roles/components/revoke-user-role-dialog'

import { DataTable } from '@identity/ui/data-table'
import { Badge } from '@identity/ui/components/badge'
import {
  Alert,
  AlertDescription,
  AlertTitle,
} from '@identity/ui/components/alert'
import { Link, useNavigate } from '@tanstack/react-router'
import { ShieldPlus, TriangleAlert } from 'lucide-react'
import { useMemo, useState } from 'react'

import { AsyncState } from '#/components/async-state'
import { CollectionToolbar } from '#/components/resource-table'
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

import {
  sameVariable,
  useConsoleQuery,
} from '#/lib/graphql/use-console-query'
import { cursorPage } from '#/modules/user-management/lib/cursor-page'

import { rbacScope } from '#/modules/user-management/lib/rbac-scope'
import { useUserDetailContext } from '#/modules/user-management/users/components/user-detail-context'
import {
  AuthorizationSourceFilter,
  canFilterBySource,
  sourceVariable,
  type AuthorizationSourceFilterValue,
} from '#/modules/user-management/authorization/components/authorization-source-filter'
import { useAuthorizationLabels } from '#/modules/user-management/authorization/hooks/use-authorization-labels'
import { UserSelectField } from '#/modules/user-management/users/components/user-form-fields'

type AssignmentStatus = 'any' | 'active' | 'revoked'


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
  const sourceFilterable = canFilterBySource(scope)
  const [sourceFilter, setSourceFilter] =
    useState<AuthorizationSourceFilterValue>('any')
  // Without group reads the server only allows the direct list.
  const source = sourceFilterable ? sourceVariable(sourceFilter) : 'DIRECT'
  const [after, setAfter] = useState<string | undefined>()
  const [before, setBefore] = useState<string | undefined>()
  const [pageSize, setPageSize] = useState(10)
  const [notice, setNotice] = useState<RbacNotice | null>(null)
  const variables = useMemo<ConsoleUserRolesQueryVariables | null>(
    () =>
      scope.usersRead && scope.assignmentsRead && scope.rolesRead
        ? {
            userId,
            source,
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
      scope.assignmentsRead,
      scope.rolesRead,
      scope.usersRead,
      source,
      status,
      userId,
      pageSize,
    ],
  )
  const assignments = useConsoleQuery<
    ConsoleUserRolesQuery,
    ConsoleUserRolesQueryVariables
  >(
    ConsoleUserRolesDocument,
    variables,
    Boolean(variables),
    'missing_user_roles',
    { keepPreviousData: sameVariable('userId') },
  )
  const user = userDetail.user
  const connection = assignments.data?.user?.roles ?? null
  const groupIds = useMemo(
    () =>
      scope.groupsRead
        ? [
            ...new Set(
              (connection?.edges ?? []).flatMap((edge) =>
                edge.groupId ? [edge.groupId] : [],
              ),
            ),
          ]
        : [],
    [connection, scope.groupsRead],
  )
  const groupLabels = useAuthorizationLabels(groupIds)
  const groupName = (id: string) => {
    const group = groupLabels.nodes.find((node) => node.id === id)
    return group?.__typename === 'Group'
      ? (resolveLocalizedText(group.names, locale) ?? group.name)
      : t('authorizationSourceGroup')
  }

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
                <p className="mt-1 text-sm text-muted-foreground">
                  {t('userRolesListDescription')}
                </p>
              </div>
              <div className="flex shrink-0 items-center gap-2">
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
            <CollectionToolbar
              filters={
                <div className="flex flex-wrap items-start gap-2">
                  {sourceFilterable ? (
                    <AuthorizationSourceFilter
                      name="user-role-source"
                      value={sourceFilter}
                      onChange={(value) => {
                        setSourceFilter(value)
                        setAfter(undefined)
                        setBefore(undefined)
                      }}
                    />
                  ) : null}
                  <div className="w-36">
                    <UserSelectField
                      name="user-role-status"
                      label={t('rolesFilterStatusLabel')}
                      hideLabel
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
                </div>
              }
            />
            <div className="min-w-0">{renderAssignments()}</div>
            <footer className="resource-collection-pagination">
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
                  pageSize={pageSize}
                  onPageSizeChange={(size) => {
                    setPageSize(size)
                    setAfter(undefined)
                    setBefore(undefined)
                  }}
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
    return (
      <div>
        {assignments.partial ? (
          <div className="p-3">
            <Alert variant="default" className="text-warning">
              <TriangleAlert aria-hidden="true" />
              <AlertTitle>{t('rolesPartialTitle')}</AlertTitle>
              <AlertDescription>{t('rolesPartialDescription')}</AlertDescription>
              <RequestCorrelation
                requestId={assignments.requestId}
                traceId={assignments.traceId}
              />
              <ErrorDetails issues={assignments.errors} />
            </Alert>
          </div>
        ) : null}
        <DataTable
          loading={assignments.refreshing}
          loadingLabel={t('tableLoading')}
          label={t('userRolesTableLabel')}
          minWidth={960}
          columns={[
            {
              id: 'userRolesColumnRole',
              label: t('userRolesColumnRole'),
              primary: true,
            },
            {
              id: 'userRolesColumnSource',
              label: t('userRolesColumnSource'),
              primary: false,
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
          <DataTable.Body
            renderEmptyState={() => (
              <AsyncState
                kind="empty"
                compact
                title={t('userRolesEmptyTitle')}
                description={
                  status !== 'any' || sourceFilter !== 'any'
                    ? t('userRolesEmptyFilteredDescription')
                    : undefined
                }
              />
            )}
          >
            {edges.map((edge) => {
              const role = edge.node
              const roleName =
                resolveLocalizedText(role.names, locale) ?? role.name
              return (
                <DataTable.Row key={edge.cursor} id={edge.cursor}>
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
                    {edge.source === 'GROUP' && edge.groupId ? (
                      <Badge variant="secondary">
                        {scope.groupsRead ? (
                          <Link
                            to="/groups/$groupId"
                            params={{ groupId: edge.groupId }}
                            className="hover:underline"
                          >
                            {groupName(edge.groupId)}
                          </Link>
                        ) : (
                          t('authorizationSourceGroup')
                        )}
                      </Badge>
                    ) : (
                      <span className="text-sm">
                        {t('authorizationSourceDirect')}
                      </span>
                    )}
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
                    {edge.source === 'GROUP' ? (
                      <span className="text-xs text-muted-foreground">
                        {t('userRolesInheritedNotRevocable')}
                      </span>
                    ) : edge.enabled ? (
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
                        <span className="text-xs text-muted-foreground">
                          {t('userRolesNoWritePermission')}
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
