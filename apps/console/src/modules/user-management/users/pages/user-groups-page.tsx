import { TableRowActions } from '#/components/table-row-actions'
import { DataTable } from '@identity/ui/data-table'
import {
  Alert,
  Button,
  Modal,
  Pagination,
  Skeleton,
  Spinner,
  toast,
  useOverlayState,
} from '@heroui/react'
import { Link, useNavigate } from '@tanstack/react-router'
import { Search, UserMinus, UserPlus } from 'lucide-react'
import { useEffect, useMemo, useRef, useState } from 'react'

import { AsyncState } from '#/components/async-state'
import { ErrorDetails } from '#/components/error-details'
import { RequestCorrelation } from '#/components/request-correlation'
import { StepUpPanel } from '#/components/step-up-panel'
import {
  ConsoleGroupsDocument,
  ConsoleUserGroupsDocument,
  type AddGroupMemberInput,
  type ConsoleGroupsQuery,
  type ConsoleGroupsQueryVariables,
  type ConsoleUserGroupsQuery,
  type ConsoleUserGroupsQueryVariables,
  type RemoveGroupMemberInput,
} from '#/gql/graphql'
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
  RbacMutationFeedback,
  RbacNoticeAlert,
  type RbacNotice,
} from '#/modules/user-management/components/rbac-feedback'
import { ConsoleWorkspaceGate } from '#/modules/user-management/components/workspace-gate'
import {
  GroupKindChip,
  GroupStatusChip,
} from '#/modules/user-management/groups/components/group-status'
import { useGroupMemberMutations } from '#/modules/user-management/groups/hooks/use-group-members'
import { resolveLocalizedText } from '#/modules/user-management/groups/lib/groups-search'
import { useConsoleQuery } from '#/modules/user-management/lib/console-query'
import { cursorPage } from '#/modules/user-management/lib/cursor-page'
import { clearDraft, readDraft, writeDraft } from '#/lib/draft-storage'
import {
  rbacConflict,
  type RbacFeedbackState,
} from '#/modules/user-management/lib/rbac-errors'
import { rbacScope } from '#/modules/user-management/lib/rbac-scope'
import { RbacAccessRestricted } from '#/modules/user-management/roles/components/role-access'
import { useUserDetailContext } from '#/modules/user-management/users/components/user-detail-context'
import { UserTextField } from '#/modules/user-management/users/components/user-form-fields'

const PAGE_SIZE = 10
const GROUP_PICKER_PAGE_SIZE = 10

type UserGroupsConnection = NonNullable<
  NonNullable<ConsoleUserGroupsQuery['user']>['groups']
>
type MembershipGroup = UserGroupsConnection['edges'][number]['node']
type GroupPickerNode = NonNullable<
  ConsoleGroupsQuery['groups']
>['edges'][number]['node']

interface AddMembershipDraft {
  groupId: string
  groupVersion: string
}

function addDraftKey(userId: string): string {
  return `identity.console.user-group-add.${userId}`
}

function readStringField(value: unknown, field: string): string {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return ''
  const candidate = (value as Record<string, unknown>)[field]
  return typeof candidate === 'string' ? candidate : ''
}

function readAddDraft(key: string): AddMembershipDraft {
  const stored = readDraft<unknown>(key)
  return {
    groupId: readStringField(stored, 'groupId'),
    groupVersion: readStringField(stored, 'groupVersion'),
  }
}

/**
 * The shared feedback component reports a version conflict with role-oriented
 * wording. Group membership conflicts keep the same recovery actions but use
 * group-specific copy.
 */
function UserGroupMutationFeedback({
  feedback,
  onReload,
  reloadPending,
}: {
  feedback: RbacFeedbackState
  onReload: () => void
  reloadPending: boolean
}) {
  const t = useTranslator()
  const conflict = rbacConflict(feedback.errors)

  if (feedback.stepUp || !conflict.conflict) {
    return (
      <RbacMutationFeedback
        feedback={feedback}
        onReload={onReload}
        reloadPending={reloadPending}
      />
    )
  }

  return (
    <Alert status="warning">
      <Alert.Indicator />
      <Alert.Content>
        <Alert.Title>{t('userGroupsConflictTitle')}</Alert.Title>
        <Alert.Description>
          {t('userGroupsConflictDescription')}
        </Alert.Description>
        <p className="mt-2 text-xs text-muted">
          {conflict.currentVersion
            ? t('rbacConflictCurrentVersion', {
                version: conflict.currentVersion,
              })
            : t('rbacConflictUnknownVersion')}
        </p>
        <RequestCorrelation
          requestId={feedback.requestId}
          traceId={feedback.traceId}
        />
        <ErrorDetails issues={feedback.errors} />
        <div className="mt-3">
          <Button
            size="sm"
            variant="secondary"
            isDisabled={reloadPending}
            onPress={onReload}
          >
            {reloadPending ? (
              <Spinner size="sm" aria-label={t('rbacReloading')} />
            ) : null}
            {t('rbacReload')}
          </Button>
        </div>
      </Alert.Content>
    </Alert>
  )
}

export function UserGroupsPage({ userId }: { userId: string }) {
  const t = useTranslator()
  const { locale } = useLocale()
  const navigate = useNavigate()
  const workspace = useWorkspace()
  const scope = useMemo(
    () => rbacScope(workspace.data?.effectivePermissions),
    [workspace.data?.effectivePermissions],
  )
  const userDetail = useUserDetailContext()
  const [query, setQuery] = useState('')
  const [appliedQuery, setAppliedQuery] = useState('')
  const [after, setAfter] = useState<string | undefined>()
  const [before, setBefore] = useState<string | undefined>()
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
            ...cursorPage(PAGE_SIZE, after, before),
          }
        : null,
    [after, appliedQuery, before, canRead, userId],
  )
  const memberships = useConsoleQuery<
    ConsoleUserGroupsQuery,
    ConsoleUserGroupsQueryVariables
  >(
    ConsoleUserGroupsDocument,
    variables,
    'ConsoleUserGroups',
    Boolean(variables),
    'missing_user_groups',
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
            stepUp={scope.usersReadStepUp}
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
            stepUp={scope.groupsReadStepUp}
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
            stepUp={scope.groupMembershipsReadStepUp}
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
          {scope.groupMembershipsWriteStepUp ? (
            <StepUpPanel
              stepUp={{ source: 'graphql', acrValues: 'aal2' }}
              hideDetails
              description={t('rbacStepUpDescription')}
              note={t('userGroupsWriteStepUpNote')}
            />
          ) : null}
          {!scope.groupMembershipsWriteReady &&
          !scope.groupMembershipsWriteStepUp ? (
            <Alert status="warning">
              <Alert.Indicator />
              <Alert.Content>
                <Alert.Title>{t('userGroupsNoWritePermission')}</Alert.Title>
                <Alert.Description>
                  {t('userGroupsNoWriteDescription')}
                </Alert.Description>
              </Alert.Content>
            </Alert>
          ) : null}

          <section className="space-y-4">
            <header className="flex flex-col gap-3 py-2 lg:flex-row lg:items-end lg:justify-between">
              <div>
                <h2 className="text-base font-semibold">
                  {t('userGroupsListTitle')}
                </h2>
                <p className="mt-1 text-sm text-muted">
                  {t('userGroupsListDescription')}
                </p>
              </div>
              <div className="flex flex-col gap-2 sm:flex-row sm:items-end">
                <form
                  className="flex min-w-0 flex-wrap items-end gap-2"
                  onSubmit={(event) => {
                    event.preventDefault()
                    setAppliedQuery(query.trim())
                    setAfter(undefined)
                    setBefore(undefined)
                  }}
                >
                  <div className="w-56 max-w-full">
                    <UserTextField
                      name="user-group-search"
                      label={t('userGroupsSearchLabel')}
                      value={query}
                      onChange={setQuery}
                      placeholder={t('userGroupsSearchPlaceholder')}
                      maxLength={256}
                    />
                  </div>
                  <Button type="submit" variant="secondary">
                    <Search className="size-4" aria-hidden="true" />
                    {t('userGroupsSearchAction')}
                  </Button>
                </form>
                {readyUser && scope.groupMembershipsWriteReady ? (
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
                ) : scope.groupMembershipsWriteReady ? (
                  <UserDetailActionSkeleton
                    label={t('userGroupsAddAction')}
                    icon={<UserPlus className="size-4" />}
                  />
                ) : null}
              </div>
            </header>
            <div className="min-w-0">{renderMemberships()}</div>
            <footer className="border-t border-separator pt-4">
              {connection && memberships.status === 'ready' ? (
                <Pagination aria-label={t('userGroupsPagination')}>
                  <Pagination.Summary>
                    {t('userGroupsPageSummary', { count: edges.length })}
                  </Pagination.Summary>
                  <Pagination.Content>
                    <Pagination.Item>
                      <Pagination.Previous
                        isDisabled={
                          !connection.pageInfo.hasPreviousPage ||
                          !connection.pageInfo.startCursor
                        }
                        onPress={() => {
                          if (connection.pageInfo.startCursor) {
                            setBefore(connection.pageInfo.startCursor)
                            setAfter(undefined)
                          }
                        }}
                      >
                        <Pagination.PreviousIcon />
                        {t('previousPage')}
                      </Pagination.Previous>
                    </Pagination.Item>
                    <Pagination.Item>
                      <Pagination.Next
                        isDisabled={
                          !connection.pageInfo.hasNextPage ||
                          !connection.pageInfo.endCursor
                        }
                        onPress={() => {
                          if (connection.pageInfo.endCursor) {
                            setAfter(connection.pageInfo.endCursor)
                            setBefore(undefined)
                          }
                        }}
                      >
                        {t('nextPage')}
                        <Pagination.NextIcon />
                      </Pagination.Next>
                    </Pagination.Item>
                  </Pagination.Content>
                </Pagination>
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

    if (edges.length === 0) {
      return (
        <div className="p-4">
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
        </div>
      )
    }

    return (
      <div>
        {memberships.partial ? (
          <div className="p-3">
            <Alert status="warning">
              <Alert.Indicator />
              <Alert.Content>
                <Alert.Title>{t('groupsPartialTitle')}</Alert.Title>
                <Alert.Description>
                  {t('groupsPartialDescription')}
                </Alert.Description>
                <RequestCorrelation
                  requestId={memberships.requestId}
                  traceId={memberships.traceId}
                />
                <ErrorDetails issues={memberships.errors} />
              </Alert.Content>
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
          <DataTable.Body>
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
                  {readyUser && scope.groupMembershipsWriteReady ? (
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
                    <span className="text-xs text-muted">
                      {scope.groupMembershipsWriteStepUp
                        ? t('userGroupsWriteStepUpHint')
                        : t('userGroupsNoWritePermission')}
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
          className="font-medium text-foreground underline-offset-4 hover:underline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-focus"
        >
          {name}
        </Link>
        {description ? (
          <p className="mt-1 max-w-md text-xs leading-5 text-muted">
            {description}
          </p>
        ) : null}
      </div>
    )
  }
}

function AddGroupMembershipDialog({
  userId,
  username,
  onAdded,
  onReload,
  reloadPending,
}: {
  userId: string
  username: string
  onAdded: () => void
  onReload: () => void
  reloadPending: boolean
}) {
  const t = useTranslator()
  const state = useOverlayState()
  const mutations = useGroupMemberMutations()
  const draftKey = addDraftKey(userId)
  const stored = useMemo(() => readAddDraft(draftKey), [draftKey])
  const [query, setQuery] = useState('')
  const [appliedQuery, setAppliedQuery] = useState('')
  const [after, setAfter] = useState<string | undefined>()
  const [before, setBefore] = useState<string | undefined>()
  const [selectedGroupId, setSelectedGroupId] = useState<string | null>(() =>
    stored.groupId ? stored.groupId : null,
  )
  const [selectedGroupVersion, setSelectedGroupVersion] = useState(
    () => stored.groupVersion,
  )
  const [feedback, setFeedback] = useState<RbacFeedbackState | null>(null)
  const [localError, setLocalError] = useState<string | null>(null)
  const [pending, setPending] = useState(false)
  const submitting = useRef(false)
  const opened = useRef(false)
  const completed = useRef(false)

  const variables = useMemo<ConsoleGroupsQueryVariables | null>(
    () =>
      state.isOpen
        ? {
            filter: appliedQuery ? { query: appliedQuery } : {},
            orderBy: 'CREATED_AT_DESC',
            ...cursorPage(GROUP_PICKER_PAGE_SIZE, after, before),
          }
        : null,
    [after, appliedQuery, before, state.isOpen],
  )
  const groups = useConsoleQuery<
    ConsoleGroupsQuery,
    ConsoleGroupsQueryVariables
  >(
    ConsoleGroupsDocument,
    variables,
    'ConsoleGroups',
    Boolean(variables),
    'missing_group_connection',
  )

  useEffect(() => {
    if (state.isOpen) {
      opened.current = true
      return
    }
    if (!opened.current) return
    if (!completed.current) clearDraft(draftKey)
    setQuery('')
    setAppliedQuery('')
    setAfter(undefined)
    setBefore(undefined)
    setSelectedGroupId(null)
    setSelectedGroupVersion('')
    setFeedback(null)
    setLocalError(null)
    setPending(false)
    completed.current = false
  }, [draftKey, state.isOpen])

  useEffect(() => {
    if (!state.isOpen) return
    if (!selectedGroupId) return
    writeDraft(draftKey, {
      groupId: selectedGroupId,
      groupVersion: selectedGroupVersion,
    } satisfies AddMembershipDraft)
  }, [draftKey, selectedGroupId, selectedGroupVersion, state.isOpen])

  useEffect(() => {
    if (!selectedGroupId) return
    const node = groups.data?.groups.edges.find(
      (edge) => edge.node.id === selectedGroupId,
    )?.node
    if (!node) return
    if (node.version === selectedGroupVersion) return
    setSelectedGroupVersion(node.version)
  }, [groups.data, selectedGroupId, selectedGroupVersion])

  async function submit() {
    if (submitting.current) return
    if (!selectedGroupId) {
      setLocalError(t('userGroupsSelectGroupRequired'))
      return
    }
    if (!selectedGroupVersion) {
      setLocalError(t('userGroupsVersionUnavailable'))
      return
    }
    submitting.current = true
    setPending(true)
    setFeedback(null)
    setLocalError(null)
    const input: AddGroupMemberInput = {
      groupId: selectedGroupId,
      userId,
      expectedVersion: selectedGroupVersion,
    }
    try {
      const result = await mutations.add(input)
      const payload = result.data?.addGroupMember ?? null
      if (!payload) {
        setFeedback({
          errors: result.errors,
          failure: result.failure ?? {
            kind: 'invalid_response',
            code: 'missing_add_group_member_payload',
            requestId: result.requestId,
            traceId: result.traceId,
          },
          stepUp: result.stepUp,
          requestId: result.requestId,
          traceId: result.traceId,
          forbidden: result.forbidden,
        })
        return
      }
      completed.current = true
      clearDraft(draftKey)
      state.close()
      toast.success(t('userGroupsAddedToast'), {
        description: t('userGroupsAddedCommitted'),
      })
      if (result.partial) toast.warning(t('rbacPartialMutationNote'))
      onAdded()
    } catch {
      setFeedback({
        errors: [],
        failure: { kind: 'network', code: 'add_group_member_request_failed' },
        forbidden: false,
      })
    } finally {
      submitting.current = false
      setPending(false)
    }
  }

  const connection = groups.data?.groups ?? null
  const edges = connection?.edges ?? []
  const selectedVisible = edges.some(({ node }) => node.id === selectedGroupId)
  const conflict = feedback ? rbacConflict(feedback.errors).conflict : false

  return (
    <>
      <Button onPress={state.open}>
        <UserPlus className="size-4" aria-hidden="true" />
        {t('userGroupsAddAction')}
      </Button>
      <Modal state={state}>
        <Modal.Backdrop isDismissable={!pending}>
          <Modal.Container size="lg">
            <Modal.Dialog>
              {({ close }) => (
                <>
                  <Modal.CloseTrigger
                    aria-label={t('close')}
                    isDisabled={pending}
                  />
                  <Modal.Header>
                    <Modal.Heading>{t('userGroupsAddTitle')}</Modal.Heading>
                  </Modal.Header>
                  <Modal.Body>
                    <p className="text-sm leading-6 text-muted">
                      {t('userGroupsAddDescription', { user: username })}
                    </p>
                    <form
                      className="collection-filter-controls mt-4 flex items-end gap-2"
                      onSubmit={(event) => {
                        event.preventDefault()
                        setAppliedQuery(query.trim())
                        setAfter(undefined)
                        setBefore(undefined)
                      }}
                    >
                      <div className="min-w-0 flex-1">
                        <UserTextField
                          name="user-group-add-search"
                          label={t('userGroupsSearchLabel')}
                          value={query}
                          onChange={setQuery}
                          placeholder={t('userGroupsSearchPlaceholder')}
                          maxLength={256}
                        />
                      </div>
                      <Button type="submit">
                        <Search className="size-4" aria-hidden="true" />
                        {t('userGroupsSearchAction')}
                      </Button>
                    </form>

                    {selectedGroupId && !selectedVisible ? (
                      <p className="mt-3 break-all font-mono text-xs text-muted">
                        {t('userGroupsAddSelectedGroup', {
                          group: selectedGroupId,
                        })}
                      </p>
                    ) : null}

                    <div
                      className="mt-4 max-h-72 overflow-y-auto rounded-field border border-border"
                      role="region"
                      aria-label={t('userGroupsAddResultsLabel')}
                    >
                      {groups.status === 'error' ? (
                        <div className="p-3">
                          <AsyncState
                            kind={groups.forbidden ? 'forbidden' : 'error'}
                            compact
                            title={t(
                              failureTitleKey(groups.failure, groups.forbidden),
                            )}
                            description={t(
                              failureDescriptionKey(
                                groups.failure,
                                groups.forbidden,
                              ),
                            )}
                            requestId={groups.requestId}
                            traceId={groups.traceId}
                            issues={groups.errors}
                            onRetry={() => void groups.refresh()}
                          />
                        </div>
                      ) : groups.status !== 'ready' ? (
                        <div
                          className="space-y-2 p-3"
                          role="status"
                          aria-label={t('userGroupsLoading')}
                        >
                          <span className="sr-only">
                            {t('userGroupsLoading')}
                          </span>
                          <Skeleton className="h-12 w-full" />
                          <Skeleton className="h-12 w-full" />
                        </div>
                      ) : edges.length === 0 ? (
                        <p className="p-4 text-sm text-muted">
                          {t('userGroupsAddNoCandidates')}
                        </p>
                      ) : (
                        <ul className="divide-y divide-separator">
                          {edges.map(({ node }) => (
                            <GroupPickerRow
                              key={node.id}
                              node={node}
                              checked={selectedGroupId === node.id}
                              onSelect={() => {
                                setSelectedGroupId(node.id)
                                setSelectedGroupVersion(node.version)
                                setLocalError(null)
                                setFeedback(null)
                              }}
                            />
                          ))}
                        </ul>
                      )}
                    </div>

                    {connection ? (
                      <div className="mt-2 flex justify-end gap-2">
                        <Button
                          size="sm"
                          variant="secondary"
                          isDisabled={!connection.pageInfo.hasPreviousPage}
                          onPress={() => {
                            const cursor = connection.pageInfo.startCursor
                            if (cursor) {
                              setBefore(cursor)
                              setAfter(undefined)
                            }
                          }}
                        >
                          {t('previousPage')}
                        </Button>
                        <Button
                          size="sm"
                          variant="secondary"
                          isDisabled={!connection.pageInfo.hasNextPage}
                          onPress={() => {
                            const cursor = connection.pageInfo.endCursor
                            if (cursor) {
                              setAfter(cursor)
                              setBefore(undefined)
                            }
                          }}
                        >
                          {t('nextPage')}
                        </Button>
                      </div>
                    ) : null}

                    {localError ? (
                      <p role="alert" className="mt-3 text-xs text-danger">
                        {localError}
                      </p>
                    ) : null}

                    {feedback ? (
                      <div className="mt-4">
                        <UserGroupMutationFeedback
                          feedback={feedback}
                          onReload={() => {
                            setFeedback(null)
                            void groups.refresh()
                            onReload()
                          }}
                          reloadPending={reloadPending || groups.refreshing}
                        />
                      </div>
                    ) : null}
                  </Modal.Body>
                  <Modal.Footer>
                    <Button
                      variant="secondary"
                      isDisabled={pending}
                      onPress={close}
                    >
                      {t('cancel')}
                    </Button>
                    <Button
                      isDisabled={
                        pending ||
                        !selectedGroupId ||
                        !selectedGroupVersion ||
                        conflict
                      }
                      onPress={() => void submit()}
                    >
                      {pending ? (
                        <Spinner size="sm" aria-label={t('working')} />
                      ) : null}
                      {t('userGroupsAddConfirm')}
                    </Button>
                  </Modal.Footer>
                </>
              )}
            </Modal.Dialog>
          </Modal.Container>
        </Modal.Backdrop>
      </Modal>
    </>
  )
}

function GroupPickerRow({
  node,
  checked,
  onSelect,
}: {
  node: GroupPickerNode
  checked: boolean
  onSelect: () => void
}) {
  const { locale } = useLocale()
  const name = resolveLocalizedText(node.names, locale) ?? node.name ?? node.id
  return (
    <li>
      <label className="flex cursor-pointer items-start gap-3 p-3 hover:bg-surface-secondary">
        <input
          type="radio"
          name="user-group-add-selection"
          className="mt-1 size-4"
          checked={checked}
          onChange={onSelect}
        />
        <span className="min-w-0">
          <span className="block text-sm font-medium">{name}</span>
          <span className="mt-1 flex flex-wrap items-center gap-1">
            <GroupKindChip builtIn={node.builtIn} />
            <GroupStatusChip enabled={node.enabled} />
          </span>
        </span>
      </label>
    </li>
  )
}

function RemoveGroupMembershipDialog({
  group,
  userId,
  username,
  onRemoved,
  onReload,
  reloadPending,
}: {
  group: MembershipGroup
  userId: string
  username: string
  onRemoved: () => void
  onReload: () => void
  reloadPending: boolean
}) {
  const t = useTranslator()
  const { locale } = useLocale()
  const state = useOverlayState()
  const mutations = useGroupMemberMutations()
  const [feedback, setFeedback] = useState<RbacFeedbackState | null>(null)
  const [pending, setPending] = useState(false)
  const submitting = useRef(false)

  const groupName =
    resolveLocalizedText(group.names, locale) ?? group.name ?? group.id
  const conflict = feedback ? rbacConflict(feedback.errors).conflict : false

  async function submit() {
    if (submitting.current) return
    if (!group.version) return
    submitting.current = true
    setPending(true)
    setFeedback(null)
    const input: RemoveGroupMemberInput = {
      groupId: group.id,
      userId,
      expectedVersion: group.version,
    }
    try {
      const result = await mutations.remove(input)
      const payload = result.data?.removeGroupMember ?? null
      if (!payload) {
        setFeedback({
          errors: result.errors,
          failure: result.failure ?? {
            kind: 'invalid_response',
            code: 'missing_remove_group_member_payload',
            requestId: result.requestId,
            traceId: result.traceId,
          },
          stepUp: result.stepUp,
          requestId: result.requestId,
          traceId: result.traceId,
          forbidden: result.forbidden,
        })
        return
      }
      state.close()
      toast.success(t('userGroupsRemovedToast'), {
        description: t('userGroupsRemovedCommitted'),
      })
      if (result.partial) toast.warning(t('rbacPartialMutationNote'))
      onRemoved()
    } catch {
      setFeedback({
        errors: [],
        failure: {
          kind: 'network',
          code: 'remove_group_member_request_failed',
        },
        forbidden: false,
      })
    } finally {
      submitting.current = false
      setPending(false)
    }
  }

  return (
    <>
      <TableRowActions
        subject={groupName}
        actions={[
          {
            id: 'remove',
            label: t('userGroupsRemoveAction'),
            onAction: state.open,
            danger: true,
            icon: <UserMinus className="size-4" aria-hidden="true" />,
            isDisabled: !group.version,
          },
        ]}
      />
      <Modal state={state}>
        <Modal.Backdrop isDismissable={!pending}>
          <Modal.Container size="md">
            <Modal.Dialog>
              {({ close }) => (
                <>
                  <Modal.CloseTrigger
                    aria-label={t('close')}
                    isDisabled={pending}
                  />
                  <Modal.Header>
                    <Modal.Heading>{t('userGroupsRemoveTitle')}</Modal.Heading>
                  </Modal.Header>
                  <Modal.Body>
                    <p className="text-sm leading-6 text-muted">
                      {t('userGroupsRemoveDescription', {
                        user: username,
                        group: groupName,
                      })}
                    </p>
                    {feedback ? (
                      <div className="mt-4">
                        <UserGroupMutationFeedback
                          feedback={feedback}
                          onReload={() => {
                            setFeedback(null)
                            onReload()
                          }}
                          reloadPending={reloadPending}
                        />
                      </div>
                    ) : null}
                  </Modal.Body>
                  <Modal.Footer>
                    <Button
                      variant="secondary"
                      isDisabled={pending}
                      onPress={close}
                    >
                      {t('cancel')}
                    </Button>
                    <Button
                      variant="danger"
                      isDisabled={pending || !group.version || conflict}
                      onPress={() => void submit()}
                    >
                      {pending ? (
                        <Spinner size="sm" aria-label={t('working')} />
                      ) : null}
                      {t('userGroupsRemoveConfirm')}
                    </Button>
                  </Modal.Footer>
                </>
              )}
            </Modal.Dialog>
          </Modal.Container>
        </Modal.Backdrop>
      </Modal>
    </>
  )
}
