import { TableRowActions } from '#/components/table-row-actions'
import { DataTable } from '@identity/ui/data-table'
import {
  Alert,
  Button,
  Chip,
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
  ConsoleUsersDocument,
  type AddGroupMemberInput,
  type ConsoleGroupMembersQuery,
  type ConsoleGroupMembersQueryVariables,
  type ConsoleUsersQuery,
  type ConsoleUsersQueryVariables,
  type RemoveGroupMemberInput,
} from '#/gql/graphql'
import { formatDateTime } from '#/lib/format'
import {
  failureDescriptionKey,
  failureTitleKey,
} from '#/lib/graphql/presentation'
import { useLocale, useTranslator } from '#/lib/i18n'
import { useWorkspace } from '#/lib/workspace'
import {
  RbacMutationFeedback,
  RbacNoticeAlert,
  type RbacNotice,
} from '#/modules/user-management/components/rbac-feedback'
import { ConsoleWorkspaceGate } from '#/modules/user-management/components/workspace-gate'
import {
  useGroupMemberMutations,
  useGroupMembers,
} from '#/modules/user-management/groups/hooks/use-group-members'
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
import {
  UserSelectField,
  UserTextField,
} from '#/modules/user-management/users/components/user-form-fields'

const PAGE_SIZE = 10
const USER_PICKER_PAGE_SIZE = 10

type GroupNode = NonNullable<ConsoleGroupMembersQuery['group']>
type MemberNode = GroupNode['members']['edges'][number]['node']
type MemberStatus = 'any' | 'enabled' | 'disabled'

function addDraftKey(groupId: string): string {
  return `identity.console.group-member-add.${groupId}`
}

function readStringField(value: unknown, field: string): string {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return ''
  const candidate = (value as Record<string, unknown>)[field]
  return typeof candidate === 'string' ? candidate : ''
}

function nextPageState(
  setAfter: (value: string | undefined) => void,
  setBefore: (value: string | undefined) => void,
) {
  return {
    next(cursor: string | null) {
      if (!cursor) return
      setAfter(cursor)
      setBefore(undefined)
    },
    previous(cursor: string | null) {
      if (!cursor) return
      setBefore(cursor)
      setAfter(undefined)
    },
  }
}

export function GroupMembersPage({ groupId }: { groupId: string }) {
  const t = useTranslator()
  const { locale, timeZone } = useLocale()
  const navigate = useNavigate()
  const workspace = useWorkspace()
  const scope = useMemo(
    () => rbacScope(workspace.data?.effectivePermissions),
    [workspace.data?.effectivePermissions],
  )
  const canRead = scope.groupsRead && scope.groupMembershipsRead
  const [status, setStatus] = useState<MemberStatus>('any')
  const [after, setAfter] = useState<string | undefined>()
  const [before, setBefore] = useState<string | undefined>()
  const [notice, setNotice] = useState<RbacNotice | null>(null)

  const variables = useMemo<ConsoleGroupMembersQueryVariables | null>(
    () =>
      canRead
        ? {
            groupId,
            filter: status === 'any' ? {} : { enabled: status === 'enabled' },
            orderBy: 'CREATED_AT_DESC',
            ...cursorPage(PAGE_SIZE, after, before),
            includeUser: scope.usersRead,
          }
        : null,
    [after, before, canRead, groupId, scope.usersRead, status],
  )
  const members = useGroupMembers(variables)
  const pageState = nextPageState(setAfter, setBefore)
  const group = members.data?.group ?? null

  if (!canRead) {
    return (
      <ConsoleWorkspaceGate>
        <RbacAccessRestricted
          title={
            !scope.groupsRead ? 'groupsNoReadTitle' : 'groupMembersNoReadTitle'
          }
          description={
            !scope.groupsRead
              ? 'groupsNoReadDescription'
              : 'groupMembersNoReadDescription'
          }
          stepUp={
            !scope.groupsRead
              ? scope.groupsReadStepUp
              : scope.groupMembershipsReadStepUp
          }
          onBack={() => void navigate({ to: '/groups' })}
          backLabel="backToGroups"
        />
      </ConsoleWorkspaceGate>
    )
  }

  if (members.status === 'error') {
    return (
      <ConsoleWorkspaceGate>
        {members.stepUp ? (
          <StepUpPanel
            stepUp={members.stepUp}
            hideDetails
            description={t('rbacStepUpDescription')}
            note={t('rbacStepUpNote')}
          />
        ) : (
          <AsyncState
            kind={members.forbidden ? 'forbidden' : 'error'}
            title={t(failureTitleKey(members.failure, members.forbidden))}
            description={t(
              failureDescriptionKey(members.failure, members.forbidden),
            )}
            requestId={members.requestId}
            traceId={members.traceId}
            issues={members.errors}
            onRetry={() => void members.refresh()}
          />
        )}
      </ConsoleWorkspaceGate>
    )
  }

  if (members.status === 'ready' && !group) {
    return (
      <ConsoleWorkspaceGate>
        <AsyncState
          kind="notFound"
          title={t('notFoundTitle')}
          description={t('notFoundDescription')}
        />
      </ConsoleWorkspaceGate>
    )
  }

  if (members.status !== 'ready' || !group) {
    return (
      <ConsoleWorkspaceGate>
        <AsyncState kind="loading" title={t('loading')} />
      </ConsoleWorkspaceGate>
    )
  }

  const readyGroup = group
  const groupName =
    resolveLocalizedText(readyGroup.names, locale) ??
    readyGroup.name ??
    readyGroup.id

  return (
    <ConsoleWorkspaceGate>
      <div className="space-y-4">
        {notice ? (
          <RbacNoticeAlert notice={notice} onDismiss={() => setNotice(null)} />
        ) : null}

        {scope.groupMembershipsWriteStepUp ? (
          <StepUpPanel
            stepUp={{ source: 'graphql', acrValues: 'aal2' }}
            hideDetails
            description={t('rbacStepUpDescription')}
            note={t('groupMembersWriteStepUpNote')}
          />
        ) : null}

        {readyGroup.builtIn ? (
          <Alert status="default">
            <Alert.Indicator />
            <Alert.Content>
              <Alert.Title>{t('groupBuiltInReadonlyTitle')}</Alert.Title>
              <Alert.Description>
                {t('groupMembersBuiltInNote')}
              </Alert.Description>
            </Alert.Content>
          </Alert>
        ) : null}

        {scope.usersRead ? null : (
          <Alert status="warning">
            <Alert.Indicator />
            <Alert.Content>
              <Alert.Title>{t('groupMembersNoUsersReadTitle')}</Alert.Title>
              <Alert.Description>
                {t('groupMembersNoUsersReadDescription')}
              </Alert.Description>
            </Alert.Content>
          </Alert>
        )}

        {!scope.groupMembershipsWriteReady &&
        !scope.groupMembershipsWriteStepUp ? (
          <Alert status="warning">
            <Alert.Indicator />
            <Alert.Content>
              <Alert.Title>{t('groupMembersNoWritePermission')}</Alert.Title>
              <Alert.Description>
                {t('groupMembersNoWriteDescription')}
              </Alert.Description>
            </Alert.Content>
          </Alert>
        ) : null}

        <section className="space-y-4">
          <header className="flex flex-col gap-3 py-2 sm:flex-row sm:items-end sm:justify-between">
            <div>
              <h2 className="text-base font-semibold">
                {t('groupMembersListTitle')}
              </h2>
              <p className="mt-1 text-sm text-muted">
                {t('groupMembersListDescription')}
              </p>
            </div>
            <div className="flex flex-wrap items-end gap-2">
              <div className="w-44">
                <UserSelectField
                  name="group-member-status"
                  label={t('groupMembersStatusFilterLabel')}
                  value={status}
                  onChange={(value) => {
                    if (
                      value === 'any' ||
                      value === 'enabled' ||
                      value === 'disabled'
                    ) {
                      setStatus(value)
                      setAfter(undefined)
                      setBefore(undefined)
                    }
                  }}
                  options={[
                    { id: 'any', label: t('groupMembersFilterAll') },
                    { id: 'enabled', label: t('groupMembersFilterActive') },
                    { id: 'disabled', label: t('groupMembersFilterRemoved') },
                  ]}
                />
              </div>
              {scope.groupMembershipsWriteReady && scope.usersRead ? (
                <AddMemberDialog
                  groupId={readyGroup.id}
                  groupVersion={readyGroup.version}
                  groupName={groupName}
                  onAdded={() => {
                    setNotice({
                      kind: 'success',
                      title: t('groupMembersAddedToast'),
                      description: t('groupMembersAddedCommitted'),
                    })
                    void members.refresh()
                  }}
                  onReload={() => void members.refresh()}
                  reloadPending={members.refreshing}
                />
              ) : null}
            </div>
          </header>
          <div className="p-0">{renderMembers()}</div>
          <footer className="border-t border-separator pt-4">
            <MembersPagination
              connection={readyGroup.members}
              status={members.status}
              onNext={pageState.next}
              onPrevious={pageState.previous}
            />
          </footer>
        </section>
      </div>
    </ConsoleWorkspaceGate>
  )

  function renderMembers() {
    return (
      <>
        {members.partial ? (
          <div className="p-3">
            <Alert status="warning">
              <Alert.Indicator />
              <Alert.Content>
                <Alert.Title>{t('groupsPartialTitle')}</Alert.Title>
                <Alert.Description>
                  {t('groupsPartialDescription')}
                </Alert.Description>
                <RequestCorrelation
                  requestId={members.requestId}
                  traceId={members.traceId}
                />
                <ErrorDetails issues={members.errors} />
              </Alert.Content>
            </Alert>
          </div>
        ) : null}
        {renderMemberTable(readyGroup.members.edges)}
      </>
    )
  }

  function renderMemberTable(edges: GroupNode['members']['edges']) {
    if (edges.length === 0) {
      return (
        <div className="p-4">
          <AsyncState
            kind="empty"
            compact
            title={
              status === 'any'
                ? t('groupMembersEmptyTitle')
                : t('groupMembersEmptyFilteredTitle')
            }
            description={
              status === 'any'
                ? t('groupMembersEmptyDescription')
                : t('groupMembersEmptyFilteredDescription')
            }
          />
        </div>
      )
    }
    return (
      <DataTable
        label={t('groupMembersTableLabel')}
        minWidth={900}
        columns={[
          {
            id: 'groupMembersColumnMember',
            label: t('groupMembersColumnMember'),
            primary: true,
          },
          {
            id: 'groupMembersColumnStatus',
            label: t('groupMembersColumnStatus'),
            primary: false,
          },
          {
            id: 'groupMembersColumnCreated',
            label: t('groupMembersColumnCreated'),
            primary: false,
          },
          {
            id: 'groupMembersColumnActions',
            label: t('groupMembersColumnActions'),
            primary: false,
          },
        ]}
      >
        <DataTable.Body>
          {edges.map(({ node }) => (
            <DataTable.Row key={node.id} id={node.id}>
              <DataTable.Cell>{renderMemberIdentity(node)}</DataTable.Cell>
              <DataTable.Cell>
                {node.enabled && !node.revokedAt ? (
                  <Chip size="sm" variant="soft" color="success">
                    <Chip.Label>{t('groupMembersStatusActive')}</Chip.Label>
                  </Chip>
                ) : (
                  <Chip size="sm" variant="soft" color="default">
                    <Chip.Label>{t('groupMembersStatusRemoved')}</Chip.Label>
                  </Chip>
                )}
              </DataTable.Cell>
              <DataTable.Cell>
                <span className="whitespace-nowrap text-sm">
                  {formatDateTime(node.createdAt, locale, timeZone)}
                </span>
                {node.revokedAt ? (
                  <span className="mt-0.5 block whitespace-nowrap text-xs text-muted">
                    {formatDateTime(node.revokedAt, locale, timeZone)}
                  </span>
                ) : null}
              </DataTable.Cell>
              <DataTable.Cell>
                {node.enabled && !node.revokedAt ? (
                  scope.groupMembershipsWriteReady ? (
                    <RemoveMemberDialog
                      node={node}
                      groupVersion={readyGroup.version}
                      onRemoved={() => {
                        setNotice({
                          kind: 'success',
                          title: t('groupMembersRemovedToast'),
                          description: t('groupMembersRemovedCommitted'),
                        })
                        void members.refresh()
                      }}
                      onReload={() => void members.refresh()}
                      reloadPending={members.refreshing}
                    />
                  ) : (
                    <span className="text-xs text-muted">
                      {t('groupMembersNoWritePermission')}
                    </span>
                  )
                ) : (
                  <span className="text-xs text-muted">
                    {t('groupMembersRevokedAt', {
                      date: formatDateTime(node.revokedAt, locale, timeZone),
                    })}
                  </span>
                )}
              </DataTable.Cell>
            </DataTable.Row>
          ))}
        </DataTable.Body>
      </DataTable>
    )
  }

  function renderMemberIdentity(node: MemberNode) {
    const user = scope.usersRead ? (node.user ?? null) : null
    return (
      <div className="min-w-52">
        {user ? (
          <>
            <Link
              to="/users/$userId"
              params={{ userId: user.id }}
              className="font-medium text-foreground underline-offset-4 hover:underline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-focus"
            >
              {user.username}
            </Link>
            {user.email ? (
              <p className="mt-0.5 break-all text-xs text-muted">
                {user.email}
              </p>
            ) : null}
            <p className="mt-1 break-all font-mono text-[11px] text-muted">
              {t('groupMembersMembershipIdLabel')}: {node.id}
            </p>
          </>
        ) : (
          <>
            <p className="break-all font-mono text-xs">{node.userId}</p>
            <p className="mt-1 break-all font-mono text-[11px] text-muted">
              {t('groupMembersMembershipIdLabel')}: {node.id}
            </p>
            {scope.usersRead ? null : (
              <p className="mt-1 text-[11px] text-muted">
                {t('groupMembersUserHidden')}
              </p>
            )}
          </>
        )}
        {node.grantedByUserId ? (
          <p className="mt-1 break-all text-[11px] text-muted">
            {t('groupMembersGrantedByLabel')}: {node.grantedByUserId}
          </p>
        ) : null}
      </div>
    )
  }
}

function MembersPagination({
  connection,
  status,
  onNext,
  onPrevious,
}: {
  connection: GroupNode['members'] | null
  status: string
  onNext: (cursor: string | null) => void
  onPrevious: (cursor: string | null) => void
}) {
  const t = useTranslator()
  if (status !== 'ready' || !connection) return null
  return (
    <Pagination aria-label={t('groupMembersPagination')}>
      <Pagination.Summary>
        {t('groupMembersPageSummary', { count: connection.edges.length })}
      </Pagination.Summary>
      <Pagination.Content>
        <Pagination.Item>
          <Pagination.Previous
            isDisabled={!connection.pageInfo.hasPreviousPage}
            onPress={() => onPrevious(connection.pageInfo.startCursor)}
          >
            <Pagination.PreviousIcon />
            {t('previousPage')}
          </Pagination.Previous>
        </Pagination.Item>
        <Pagination.Item>
          <Pagination.Next
            isDisabled={!connection.pageInfo.hasNextPage}
            onPress={() => onNext(connection.pageInfo.endCursor)}
          >
            {t('nextPage')}
            <Pagination.NextIcon />
          </Pagination.Next>
        </Pagination.Item>
      </Pagination.Content>
    </Pagination>
  )
}

function AddMemberDialog({
  groupId,
  groupVersion,
  groupName,
  onAdded,
  onReload,
  reloadPending,
}: {
  groupId: string
  groupVersion: string
  groupName: string
  onAdded: () => void
  onReload: () => void
  reloadPending: boolean
}) {
  const t = useTranslator()
  const state = useOverlayState()
  const mutations = useGroupMemberMutations()
  const draftKey = addDraftKey(groupId)
  const [query, setQuery] = useState('')
  const [appliedQuery, setAppliedQuery] = useState('')
  const [after, setAfter] = useState<string | undefined>()
  const [before, setBefore] = useState<string | undefined>()
  const [selectedUserId, setSelectedUserId] = useState<string | null>(() => {
    const stored = readDraft<unknown>(draftKey)
    return readStringField(stored, 'userId') || null
  })
  const [feedback, setFeedback] = useState<RbacFeedbackState | null>(null)
  const [localError, setLocalError] = useState<string | null>(null)
  const [pending, setPending] = useState(false)
  const submitting = useRef(false)
  const opened = useRef(false)
  const completed = useRef(false)

  const variables = useMemo<ConsoleUsersQueryVariables | null>(
    () =>
      state.isOpen
        ? {
            filter: appliedQuery ? { query: appliedQuery } : {},
            orderBy: 'USERNAME_ASC',
            ...cursorPage(USER_PICKER_PAGE_SIZE, after, before),
          }
        : null,
    [after, appliedQuery, before, state.isOpen],
  )
  const users = useConsoleQuery<ConsoleUsersQuery, ConsoleUsersQueryVariables>(
    ConsoleUsersDocument,
    variables,
    'ConsoleUsers',
    Boolean(variables),
    'missing_user_connection',
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
    setSelectedUserId(null)
    setFeedback(null)
    setLocalError(null)
    setPending(false)
    completed.current = false
  }, [draftKey, state.isOpen])

  useEffect(() => {
    if (!state.isOpen) return
    if (!selectedUserId) return
    writeDraft(draftKey, { userId: selectedUserId })
  }, [draftKey, selectedUserId, state.isOpen])

  async function submit() {
    if (submitting.current) return
    if (!selectedUserId) {
      setLocalError(t('groupMembersSelectUserRequired'))
      return
    }
    if (!groupVersion) {
      setLocalError(t('groupsVersionUnavailable'))
      return
    }
    submitting.current = true
    setPending(true)
    setFeedback(null)
    setLocalError(null)
    const input: AddGroupMemberInput = {
      groupId,
      userId: selectedUserId,
      expectedVersion: groupVersion,
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
      toast.success(t('groupMembersAddedToast'), {
        description: t('groupMembersAddedCommitted'),
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

  const connection = users.data?.users ?? null
  const edges = connection?.edges ?? []
  const selectedVisible = edges.some(({ node }) => node.id === selectedUserId)

  return (
    <>
      <Button onPress={state.open} isDisabled={!groupVersion}>
        <UserPlus className="size-4" aria-hidden="true" />
        {t('groupMembersAddAction')}
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
                    <Modal.Heading>{t('groupMembersAddTitle')}</Modal.Heading>
                  </Modal.Header>
                  <Modal.Body>
                    <p className="text-sm leading-6 text-muted">
                      {t('groupMembersAddDescription', { group: groupName })}
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
                          name="group-member-user-search"
                          label={t('groupMembersSearchUsersLabel')}
                          value={query}
                          onChange={setQuery}
                          maxLength={256}
                        />
                      </div>
                      <Button type="submit">
                        <Search className="size-4" aria-hidden="true" />
                        {t('roleUsersSearchAction')}
                      </Button>
                    </form>

                    {selectedUserId && !selectedVisible ? (
                      <p className="mt-3 break-all font-mono text-xs text-muted">
                        {t('groupMembersAddSelectedUser', {
                          user: selectedUserId,
                        })}
                      </p>
                    ) : null}

                    <div
                      className="mt-4 max-h-72 overflow-y-auto rounded-field border border-border"
                      role="region"
                      aria-label={t('groupMembersAddResultsLabel')}
                    >
                      {users.status === 'error' ? (
                        <div className="p-3">
                          <AsyncState
                            kind={users.forbidden ? 'forbidden' : 'error'}
                            compact
                            title={t(
                              failureTitleKey(users.failure, users.forbidden),
                            )}
                            description={t(
                              failureDescriptionKey(
                                users.failure,
                                users.forbidden,
                              ),
                            )}
                            requestId={users.requestId}
                            traceId={users.traceId}
                            issues={users.errors}
                            onRetry={() => void users.refresh()}
                          />
                        </div>
                      ) : users.status !== 'ready' ? (
                        <div
                          className="space-y-2 p-3"
                          role="status"
                          aria-label={t('groupMembersLoading')}
                        >
                          <span className="sr-only">
                            {t('groupMembersLoading')}
                          </span>
                          <Skeleton className="h-12 w-full" />
                          <Skeleton className="h-12 w-full" />
                        </div>
                      ) : edges.length === 0 ? (
                        <p className="p-4 text-sm text-muted">
                          {t('groupMembersNoCandidates')}
                        </p>
                      ) : (
                        <ul className="divide-y divide-separator">
                          {edges.map(({ node }) => (
                            <li key={node.id}>
                              <label className="flex cursor-pointer items-start gap-3 p-3 hover:bg-surface-secondary">
                                <input
                                  type="radio"
                                  name="group-member-user"
                                  className="mt-1 size-4"
                                  checked={selectedUserId === node.id}
                                  onChange={() => {
                                    setSelectedUserId(node.id)
                                    setLocalError(null)
                                    setFeedback(null)
                                  }}
                                />
                                <span className="min-w-0">
                                  <span className="block text-sm font-medium">
                                    {node.username}
                                  </span>
                                  <span className="block break-all text-xs text-muted">
                                    {node.email}
                                  </span>
                                  <span className="mt-1 flex flex-wrap gap-1">
                                    {node.enabled === null ||
                                    node.enabled === undefined ? null : (
                                      <Chip
                                        size="sm"
                                        variant="soft"
                                        color={
                                          node.enabled ? 'success' : 'default'
                                        }
                                      >
                                        <Chip.Label>
                                          {t(
                                            node.enabled
                                              ? 'usersEnabled'
                                              : 'usersDisabled',
                                          )}
                                        </Chip.Label>
                                      </Chip>
                                    )}
                                    {node.locked ? (
                                      <Chip
                                        size="sm"
                                        variant="soft"
                                        color="warning"
                                      >
                                        <Chip.Label>
                                          {t('usersLocked')}
                                        </Chip.Label>
                                      </Chip>
                                    ) : null}
                                  </span>
                                </span>
                              </label>
                            </li>
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
                        <RbacMutationFeedback
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
                      isDisabled={
                        pending ||
                        !selectedUserId ||
                        !groupVersion ||
                        Boolean(
                          feedback && rbacConflict(feedback.errors).conflict,
                        )
                      }
                      onPress={() => void submit()}
                    >
                      {pending ? (
                        <Spinner size="sm" aria-label={t('working')} />
                      ) : null}
                      {t('groupMembersAddConfirm')}
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

function RemoveMemberDialog({
  node,
  groupVersion,
  onRemoved,
  onReload,
  reloadPending,
}: {
  node: MemberNode
  groupVersion: string
  onRemoved: () => void
  onReload: () => void
  reloadPending: boolean
}) {
  const t = useTranslator()
  const state = useOverlayState()
  const mutations = useGroupMemberMutations()
  const [feedback, setFeedback] = useState<RbacFeedbackState | null>(null)
  const [pending, setPending] = useState(false)
  const submitting = useRef(false)
  const memberLabel = node.user?.username ?? node.userId

  async function submit() {
    if (submitting.current) return
    if (!groupVersion) return
    submitting.current = true
    setPending(true)
    setFeedback(null)
    const input: RemoveGroupMemberInput = {
      groupId: node.groupId,
      userId: node.userId,
      expectedVersion: groupVersion,
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
      toast.success(t('groupMembersRemovedToast'), {
        description: t('groupMembersRemovedCommitted'),
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
        subject={memberLabel}
        actions={[
          {
            id: 'remove',
            label: t('groupMembersRemoveAction'),
            onAction: state.open,
            danger: true,
            icon: <UserMinus className="size-4" aria-hidden="true" />,
            isDisabled: !groupVersion,
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
                    <Modal.Heading>
                      {t('groupMembersRemoveTitle')}
                    </Modal.Heading>
                  </Modal.Header>
                  <Modal.Body>
                    <p className="text-sm leading-6 text-muted">
                      {t('groupMembersRemoveDescription', {
                        user: memberLabel,
                      })}
                    </p>
                    <p className="mt-2 break-all font-mono text-xs text-muted">
                      {t('groupMembersMembershipIdLabel')}: {node.id}
                    </p>
                    {feedback ? (
                      <div className="mt-4">
                        <RbacMutationFeedback
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
                      isDisabled={
                        pending ||
                        !groupVersion ||
                        Boolean(
                          feedback && rbacConflict(feedback.errors).conflict,
                        )
                      }
                      onPress={() => void submit()}
                    >
                      {pending ? (
                        <Spinner size="sm" aria-label={t('working')} />
                      ) : null}
                      {t('groupMembersRemoveConfirm')}
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
