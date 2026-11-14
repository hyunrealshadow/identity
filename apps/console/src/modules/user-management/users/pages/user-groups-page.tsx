import { RelationPagination } from '../../components/relation-picker'
import {
  AddGroupMembershipDialog,
  RemoveGroupMembershipDialog,
} from '../../groups/components/membership-dialogs'

import { DataTable } from '@identity/ui/data-table'
import {
  Alert,
  AlertDescription,
  AlertTitle,
} from '@identity/ui/components/alert'
import { Button } from '@identity/ui/components/button'
import { Link, useNavigate } from '@tanstack/react-router'
import { Search, TriangleAlert, UserPlus } from 'lucide-react'
import { useMemo, useState } from 'react'

import { AsyncState } from '#/components/async-state'
import { CollectionToolbar } from '#/components/resource-table'
import { ErrorDetails } from '#/components/error-details'
import { RequestCorrelation } from '#/components/request-correlation'
import { StepUpPanel } from '#/components/step-up-panel'
import {
  ConsoleUserGroupsDocument,
  type ConsoleUserGroupsQuery,
  type ConsoleUserGroupsQueryVariables,
} from '#/generated/graphql'
import {
  failureDescriptionKey,
  failureTitleKey,
} from '#/lib/graphql/presentation'
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
import {
  GroupKindChip,
  GroupStatusChip,
} from '#/modules/user-management/groups/components/group-status'

import { resolveLocalizedText } from '#/modules/user-management/groups/lib/groups-search'
import {
  sameVariable,
  useConsoleQuery,
} from '#/lib/graphql/use-console-query'
import { cursorPage } from '#/modules/user-management/lib/cursor-page'

import { rbacScope } from '#/modules/user-management/lib/rbac-scope'
import { RbacAccessRestricted } from '#/modules/user-management/roles/components/role-access'
import { useUserDetailContext } from '#/modules/user-management/users/components/user-detail-context'
import { UserTextField } from '#/modules/user-management/users/components/user-form-fields'
import {
  USER_GROUPS_PAGE_SIZE,
  userGroupsAppliedFilters,
  userGroupsSearchKey,
  type UserGroupsFilters,
  type UserGroupsSearch,
} from '#/modules/user-management/users/lib/user-groups-search'
import { useUrlFilters } from '#/lib/use-url-filters'


type UserGroupsConnection = NonNullable<
  NonNullable<ConsoleUserGroupsQuery['user']>['groups']
>
type MembershipGroup = UserGroupsConnection['edges'][number]['node']
export function UserGroupsPage({
  userId,
  search,
}: {
  userId: string
  search: UserGroupsSearch
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
  // The URL always mirrors the filter form; queries use the applied filters.
  const { after, before } = search
  const pageSize = search.size ?? USER_GROUPS_PAGE_SIZE
  const { applied, go } = useUrlFilters<UserGroupsSearch, UserGroupsFilters>({
    search,
    keyOf: userGroupsSearchKey,
    appliedOf: userGroupsAppliedFilters,
    navigate: (next, { replace }) =>
      void navigate({
        to: '/users/$userId/groups',
        params: { userId },
        search: next,
        replace,
      }),
  })
  const appliedQuery = applied.q ?? ''
  const [notice, setNotice] = useState<RbacNotice | null>(null)

  const canRead =
    scope.usersRead && scope.groupsRead && scope.groupMembershipsRead

  const variables = useMemo<ConsoleUserGroupsQueryVariables | null>(
    () =>
      canRead
        ? {
            userId,
            filter: appliedQuery ? { query: appliedQuery } : {},
            orderBy: 'CREATED_AT_DESC',
            ...cursorPage(pageSize, after, before),
          }
        : null,
    [after, appliedQuery, before, canRead, userId, pageSize],
  )
  const memberships = useConsoleQuery<
    ConsoleUserGroupsQuery,
    ConsoleUserGroupsQueryVariables
  >(
    ConsoleUserGroupsDocument,
    variables,
    Boolean(variables),
    'missing_user_groups',
    { keepPreviousData: sameVariable('userId') },
  )

  const user = userDetail.user
  const connection = memberships.data?.user?.groups ?? null
  const edges = connection?.edges ?? []

  const loadingView = <UserDetailTabSkeleton userId={userId} tab="groups" />

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

  if (!scope.groupsRead) {
    return (
      <>
        <ConsoleWorkspaceGate loading={loadingView}>
          <RbacAccessRestricted
            title="userGroupsNoGroupsReadTitle"
            description="userGroupsNoGroupsReadDescription"

            onBack={() =>
              void navigate({ to: '/users/$userId', params: { userId } })
            }
            backLabel="usersBackToDetail"
          />
        </ConsoleWorkspaceGate>
      </>
    )
  }

  if (!scope.groupMembershipsRead) {
    return (
      <>
        <ConsoleWorkspaceGate loading={loadingView}>
          <RbacAccessRestricted
            title="userGroupsNoMembershipsReadTitle"
            description="userGroupsNoMembershipsReadDescription"

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
          <AsyncState
            kind="notFound"
            title={t('notFoundTitle')}
            description={t('notFoundDescription')}
          />
        </ConsoleWorkspaceGate>
      </>
    )
  }

  if (userDetail.status === 'error') {
    return (
      <>
        <ConsoleWorkspaceGate loading={loadingView}>
          {userDetail.stepUp ? (
            <StepUpPanel
              stepUp={userDetail.stepUp}
              hideDetails
              description={t('usersStepUpDescription')}
              note={t('usersStepUpNote')}
            />
          ) : (
            <AsyncState
              kind={userDetail.forbidden ? 'forbidden' : 'error'}
              title={t(
                failureTitleKey(userDetail.failure, userDetail.forbidden),
              )}
              description={t(
                failureDescriptionKey(userDetail.failure, userDetail.forbidden),
              )}
              requestId={userDetail.requestId}
              traceId={userDetail.traceId}
              issues={userDetail.errors}
              onRetry={() => void userDetail.refresh()}
            />
          )}
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

          {memberships.stepUp ? (
            <StepUpPanel
              stepUp={memberships.stepUp}
              hideDetails
              description={t('rbacStepUpDescription')}
              note={t('rbacStepUpNote')}
            />
          ) : null}

          <section className="space-y-4">
            <header className="flex flex-col gap-3 py-2 sm:flex-row sm:items-center sm:justify-between">
              <div>
                <h2 className="text-base font-semibold">
                  {t('userGroupsListTitle')}
                </h2>
                <p className="mt-1 text-sm text-muted-foreground">
                  {t('userGroupsListDescription')}
                </p>
              </div>
              <div className="flex shrink-0 items-center gap-2">
                {readyUser && scope.groupMembershipsWrite ? (
                  <AddGroupMembershipDialog
                    userId={readyUser.id}
                    username={readyUser.username}
                    onAdded={() => {
                      setNotice({
                        kind: 'success',
                        title: t('userGroupsAddedTitle'),
                        description: t('userGroupsAddedDescription'),
                      })
                      void memberships.refresh()
                    }}
                    onReload={() => void memberships.refresh()}
                    reloadPending={memberships.refreshing}
                  />
                ) : scope.groupMembershipsWrite ? (
                  <UserDetailActionSkeleton
                    label={t('userGroupsAddAction')}
                    icon={<UserPlus className="size-4" />}
                  />
                ) : null}
              </div>
            </header>
            <CollectionToolbar
              filters={
                <div className="flex flex-wrap items-start gap-2">
                  <form
                    className="flex min-w-0 flex-wrap items-start gap-2"
                    onSubmit={(event) => {
                      event.preventDefault()
                      const filters = userGroupsAppliedFilters(search)
                      // Searching again for the same text reloads the list.
                      if (!after && !before && filters.q === applied.q) {
                        void memberships.refresh()
                      }
                      go(
                        {
                          ...search,
                          ...filters,
                          after: undefined,
                          before: undefined,
                        },
                        { apply: filters },
                      )
                    }}
                  >
                    <div className="w-full sm:w-72">
                      <UserTextField
                        name="user-group-search"
                        label={t('userGroupsSearchLabel')}
                        hideLabel
                        value={search.q ?? ''}
                        onChange={(value) =>
                          go(
                            { ...search, q: value || undefined },
                            { replace: true },
                          )
                        }
                        placeholder={t('userGroupsSearchPlaceholder')}
                        maxLength={256}
                      />
                    </div>
                    <Button type="submit" variant="outline">
                      <Search className="size-4" aria-hidden="true" />
                      {t('userGroupsSearchAction')}
                    </Button>
                  </form>
                </div>
              }
            />
            <div className="min-w-0">{renderMemberships()}</div>
            <footer className="resource-collection-pagination">
              {connection && memberships.status === 'ready' ? (
                <RelationPagination
                  connection={connection}
                  variables={variables}
                  after={after}
                  before={before}
                  onNavigate={(page) =>
                    go({ ...search, after: page.after, before: page.before })
                  }
                  label={t('userGroupsPagination')}
                  isDisabled={
                    memberships.refreshing || memberships.status !== 'ready'
                  }
                  pageSize={pageSize}
                  onPageSizeChange={(size) =>
                    go({ ...search, size, after: undefined, before: undefined })
                  }
                />
              ) : memberships.status === 'idle' ||
                memberships.status === 'loading' ? (
                <UserDetailPaginationSkeleton />
              ) : null}
            </footer>
          </section>
        </div>
      </ConsoleWorkspaceGate>
    </>
  )

  function renderMemberships() {
    if (memberships.status === 'error') {
      return (
        <div className="p-4">
          <AsyncState
            kind={memberships.forbidden ? 'forbidden' : 'error'}
            title={t(
              failureTitleKey(memberships.failure, memberships.forbidden),
            )}
            description={t(
              failureDescriptionKey(memberships.failure, memberships.forbidden),
            )}
            requestId={memberships.requestId}
            traceId={memberships.traceId}
            issues={memberships.errors}
            onRetry={() => void memberships.refresh()}
          />
        </div>
      )
    }

    if (memberships.status === 'ready' && !memberships.data?.user) {
      return (
        <div className="p-4">
          <AsyncState
            kind="notFound"
            compact
            title={t('notFoundTitle')}
            description={t('notFoundDescription')}
          />
        </div>
      )
    }

    if (memberships.status !== 'ready' || !memberships.data) {
      return <UserDetailTableSkeleton label={t('userGroupsLoading')} />
    }


    return (
      <div>
        {memberships.partial ? (
          <div className="p-3">
            <Alert variant="default" className="text-warning">
              <TriangleAlert aria-hidden="true" />
              <AlertTitle>{t('groupsPartialTitle')}</AlertTitle>
              <AlertDescription>{t('groupsPartialDescription')}</AlertDescription>
              <RequestCorrelation
                requestId={memberships.requestId}
                traceId={memberships.traceId}
              />
              <ErrorDetails issues={memberships.errors} />
            </Alert>
          </div>
        ) : null}
        <DataTable
          loading={memberships.refreshing}
          loadingLabel={t('tableLoading')}
          label={t('userGroupsTableLabel')}
          minWidth={860}
          columns={[
            {
              id: 'userGroupsColumnGroup',
              label: t('userGroupsColumnGroup'),
              primary: true,
            },
            {
              id: 'userGroupsColumnKind',
              label: t('userGroupsColumnKind'),
              primary: false,
            },
            {
              id: 'userGroupsColumnStatus',
              label: t('userGroupsColumnStatus'),
              primary: false,
            },
            {
              id: 'userGroupsColumnActions',
              label: t('userGroupsColumnActions'),
              primary: false,
            },
          ]}
        >
          <DataTable.Body
            renderEmptyState={() => (
              <AsyncState
                kind="empty"
                compact
                title={
                  appliedQuery
                    ? t('userGroupsEmptyFilteredTitle')
                    : t('userGroupsEmptyTitle')
                }
                description={
                  appliedQuery
                    ? t('userGroupsEmptyFilteredDescription')
                    : t('userGroupsEmptyDescription')
                }
              />
            )}
          >
            {edges.map(({ node }) => (
              <DataTable.Row key={node.id} id={node.id}>
                <DataTable.Cell>{renderGroupIdentity(node)}</DataTable.Cell>
                <DataTable.Cell>
                  <GroupKindChip builtIn={node.builtIn} />
                </DataTable.Cell>
                <DataTable.Cell>
                  <GroupStatusChip enabled={node.enabled} />
                </DataTable.Cell>
                <DataTable.Cell>
                  {readyUser && scope.groupMembershipsWrite ? (
                    <RemoveGroupMembershipDialog
                      group={node}
                      userId={readyUser.id}
                      username={readyUser.username}
                      onRemoved={() => {
                        setNotice({
                          kind: 'success',
                          title: t('userGroupsRemovedTitle'),
                          description: t('userGroupsRemovedCommitted'),
                        })
                        void memberships.refresh()
                      }}
                      onReload={() => void memberships.refresh()}
                      reloadPending={memberships.refreshing}
                    />
                  ) : (
                    <span className="text-xs text-muted-foreground">
                      {t('userGroupsNoWritePermission')}
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

  function renderGroupIdentity(node: MembershipGroup) {
    const name =
      resolveLocalizedText(node.names, locale) ?? node.name ?? node.id
    const description =
      resolveLocalizedText(node.descriptions, locale) ?? node.description
    return (
      <div className="min-w-56">
        <Link
          to="/groups/$groupId"
          params={{ groupId: node.id }}
          className="font-medium text-foreground underline-offset-4 hover:underline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-ring"
        >
          {name}
        </Link>
        {description ? (
          <p className="mt-1 max-w-md text-xs leading-5 text-muted-foreground">
            {description}
          </p>
        ) : null}
      </div>
    )
  }
}
