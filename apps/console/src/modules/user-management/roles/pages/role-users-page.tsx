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
import { Search, UserPlus, XCircle } from 'lucide-react'
import { useEffect, useMemo, useRef, useState } from 'react'

import { AsyncState } from '#/components/async-state'
import { ErrorDetails } from '#/components/error-details'
import { RequestCorrelation } from '#/components/request-correlation'
import { StepUpPanel } from '#/components/step-up-panel'
import {
  ConsoleRoleDocument,
  ConsoleRoleUsersDocument,
  ConsoleUserRoleVersionDocument,
  ConsoleUsersDocument,
  type ConsoleRoleQuery,
  type ConsoleRoleQueryVariables,
  type ConsoleRoleUsersQuery,
  type ConsoleRoleUsersQueryVariables,
  type ConsoleUserRoleVersionQuery,
  type ConsoleUserRoleVersionQueryVariables,
  type ConsoleUsersQuery,
  type ConsoleUsersQueryVariables,
  type RevokeUserRolesInput,
} from '#/gql/graphql'
import {
  failureDescriptionKey,
  failureTitleKey,
} from '#/lib/graphql/presentation'
import { formatDateTime } from '#/lib/format'
import { useLocale, useTranslator } from '#/lib/i18n'
import { useGraphQL } from '#/lib/graphql/use-graphql'
import { useWorkspace } from '#/lib/workspace'
import {
  RbacMutationFeedback,
  type RbacNotice,
  RbacNoticeAlert,
} from '#/modules/user-management/components/rbac-feedback'
import { ConsoleWorkspaceGate } from '#/modules/user-management/components/workspace-gate'
import { RbacAccessRestricted } from '#/modules/user-management/roles/components/role-access'
import { BindingStatusChip } from '#/modules/user-management/roles/components/role-status'
import { useRoleMutations } from '#/modules/user-management/roles/hooks/role-mutations'
import {
  roleDisplayName,
  withRoleDisplayFields,
} from '#/modules/user-management/roles/lib/role-localization'
import { useConsoleQuery } from '#/modules/user-management/lib/console-query'
import { cursorPage } from '#/modules/user-management/lib/cursor-page'
import { clearDraft, readDraft, writeDraft } from '#/lib/draft-storage'
import type { RbacFeedbackState } from '#/modules/user-management/lib/rbac-errors'
import { rbacScope } from '#/modules/user-management/lib/rbac-scope'
import {
  UserSelectField,
  UserTextField,
} from '#/modules/user-management/users/components/user-form-fields'

const PAGE_SIZE = 10
const USER_PICKER_PAGE_SIZE = 10

interface AssignUserDraft {
  userId: string
}

function assignUserDraftKey(roleId: string): string {
  return `identity.console.role-user-assign.${roleId}`
}

function readAssignUserDraft(roleId: string): AssignUserDraft | null {
  const stored = readDraft<unknown>(assignUserDraftKey(roleId))
  if (!stored || typeof stored !== 'object' || Array.isArray(stored)) {
    return null
  }
  const value = stored as Record<string, unknown>
  if (typeof value.userId !== 'string' || !value.userId) return null
  return { userId: value.userId }
}

type RoleUserBinding =
  ConsoleRoleUsersQuery['roleUsers']['edges'][number]['node']
type UserStatus = 'any' | 'active' | 'revoked'

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

export function RoleUsersPage({ roleId }: { roleId: string }) {
  const t = useTranslator()
  const { locale, timeZone } = useLocale()
  const navigate = useNavigate()
  const workspace = useWorkspace()
  const scope = useMemo(
    () => rbacScope(workspace.data?.effectivePermissions),
    [workspace.data?.effectivePermissions],
  )
  const roleQuery = useConsoleQuery<
    ConsoleRoleQuery,
    ConsoleRoleQueryVariables
  >(
    ConsoleRoleDocument,
    scope.rolesRead ? { id: roleId } : null,
    'ConsoleRole',
    scope.rolesRead,
    'missing_role',
  )
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
  const pageState = nextPageState(setAfter, setBefore)

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
          stepUp={
            !scope.rolesRead ? scope.roleReadStepUp : scope.assignmentReadStepUp
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
        {scope.assignmentWriteStepUp ? (
          <StepUpPanel
            stepUp={{ source: 'graphql', acrValues: 'aal2' }}
            hideDetails
            description={t('rbacStepUpDescription')}
            note={t('rolesUsersStepUpNote')}
          />
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
              {scope.assignmentWriteReady && scope.usersRead ? (
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
            <BindingsPagination
              connection={bindings.data?.roleUsers ?? null}
              status={bindings.status}
              onNext={pageState.next}
              onPrevious={pageState.previous}
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
                    scope.assignmentWriteReady ? (
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

function BindingsPagination({
  connection,
  status,
  onNext,
  onPrevious,
}: {
  connection: ConsoleRoleUsersQuery['roleUsers'] | null
  status: string
  onNext: (cursor: string | null) => void
  onPrevious: (cursor: string | null) => void
}) {
  const t = useTranslator()
  if (status !== 'ready' || !connection) return null
  return (
    <Pagination aria-label={t('roleUsersPagination')}>
      <Pagination.Summary>
        {t('rolesPageSummary', { count: connection.edges.length })}
      </Pagination.Summary>
      <Pagination.Content>
        <Pagination.Item>
          <Pagination.Previous
            isDisabled={!connection.pageInfo.hasPreviousPage}
            onPress={() => {
              onPrevious(connection.pageInfo.startCursor)
            }}
          >
            <Pagination.PreviousIcon />
            {t('previousPage')}
          </Pagination.Previous>
        </Pagination.Item>
        <Pagination.Item>
          <Pagination.Next
            isDisabled={!connection.pageInfo.hasNextPage}
            onPress={() => {
              onNext(connection.pageInfo.endCursor)
            }}
          >
            {t('nextPage')}
            <Pagination.NextIcon />
          </Pagination.Next>
        </Pagination.Item>
      </Pagination.Content>
    </Pagination>
  )
}

function AssignUserDialog({
  role,
  onAssigned,
  onReload,
  reloadPending,
}: {
  role: NonNullable<ConsoleRoleQuery['role']>
  onAssigned: () => void
  onReload: () => void
  reloadPending: boolean
}) {
  const t = useTranslator()
  const { locale } = useLocale()
  const state = useOverlayState()
  const request = useGraphQL()
  const mutations = useRoleMutations()
  const roleName = roleDisplayName(withRoleDisplayFields(role), locale)
  const draftKey = assignUserDraftKey(role.id)
  const [query, setQuery] = useState('')
  const [appliedQuery, setAppliedQuery] = useState('')
  const [after, setAfter] = useState<string | undefined>()
  const [before, setBefore] = useState<string | undefined>()
  const [selectedUserId, setSelectedUserId] = useState<string | null>(
    () => readAssignUserDraft(role.id)?.userId ?? null,
  )
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
    if (!state.isOpen || !selectedUserId) return
    writeDraft(draftKey, { userId: selectedUserId } satisfies AssignUserDraft)
  }, [draftKey, selectedUserId, state.isOpen])

  async function submit() {
    if (submitting.current) return
    if (!selectedUserId) {
      setLocalError(t('roleUsersSelectUserRequired'))
      return
    }
    submitting.current = true
    setPending(true)
    setFeedback(null)
    setLocalError(null)
    try {
      const versionResult = await request<
        ConsoleUserRoleVersionQuery,
        ConsoleUserRoleVersionQueryVariables
      >(
        ConsoleUserRoleVersionDocument,
        { userId: selectedUserId },
        'ConsoleUserRoleVersion',
      )
      const version = versionResult.data?.userRoles.userVersion ?? ''
      if (!version) {
        setFeedback({
          errors: versionResult.errors,
          failure: versionResult.failure ?? {
            kind: 'invalid_response',
            code: 'missing_user_authorization_version',
            requestId: versionResult.requestId,
            traceId: versionResult.traceId,
          },
          stepUp: versionResult.stepUp,
          requestId: versionResult.requestId,
          traceId: versionResult.traceId,
          forbidden: versionResult.forbidden,
        })
        return
      }

      const result = await mutations.assignUserRoles({
        userId: selectedUserId,
        roleIds: [role.id],
        expectedUserVersion: version,
      })
      const payload = result.data?.assignUserRoles ?? null
      if (!payload) {
        setFeedback({
          errors: result.errors,
          failure: result.failure ?? {
            kind: 'invalid_response',
            code: 'missing_assign_user_roles_payload',
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
      clearDraft(draftKey)
      completed.current = true
      state.close()
      toast.success(t('roleUserAssignedToast'), {
        description:
          payload.createdCount > 0
            ? t('roleUserAssignedCommitted', { count: payload.createdCount })
            : t('roleUserAlreadyAssigned'),
      })
      if (result.partial) toast.warning(t('rbacPartialMutationNote'))
      onAssigned()
    } catch {
      setFeedback({
        errors: [],
        failure: { kind: 'network', code: 'assign_user_roles_request_failed' },
        forbidden: false,
      })
    } finally {
      submitting.current = false
      setPending(false)
    }
  }

  const connection = users.data?.users ?? null
  const edges = connection?.edges ?? []

  return (
    <>
      <Button onPress={state.open}>
        <UserPlus className="size-4" aria-hidden="true" />
        {t('roleUsersAssignAction')}
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
                    <Modal.Heading>{t('roleUsersAssignTitle')}</Modal.Heading>
                  </Modal.Header>
                  <Modal.Body>
                    <p className="text-sm leading-6 text-muted">
                      {t('roleUsersAssignDescription', { role: roleName })}
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
                      <UserTextField
                        name="assign-user-search"
                        label={t('roleUsersSearchUsers')}
                        value={query}
                        onChange={setQuery}
                        maxLength={256}
                      />
                      <Button type="submit">
                        <Search className="size-4" aria-hidden="true" />
                        {t('roleUsersSearchAction')}
                      </Button>
                    </form>

                    <div className="mt-4 max-h-72 overflow-y-auto rounded-field border border-border">
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
                          aria-label={t('roleUsersLoading')}
                        >
                          <span className="sr-only">
                            {t('roleUsersLoading')}
                          </span>
                          <Skeleton className="h-12 w-full" />
                          <Skeleton className="h-12 w-full" />
                        </div>
                      ) : edges.length === 0 ? (
                        <p className="p-4 text-sm text-muted">
                          {t('roleUsersNoCandidates')}
                        </p>
                      ) : (
                        <ul className="divide-y divide-separator">
                          {edges.map(({ node }) => (
                            <li key={node.id}>
                              <label className="flex cursor-pointer items-start gap-3 p-3 hover:bg-surface-secondary">
                                <input
                                  type="radio"
                                  name="assign-user"
                                  className="mt-1 size-4"
                                  checked={selectedUserId === node.id}
                                  onChange={() => setSelectedUserId(node.id)}
                                />
                                <span className="min-w-0">
                                  <span className="block text-sm font-medium">
                                    {node.username}
                                  </span>
                                  <span className="block break-all text-xs text-muted">
                                    {node.email}
                                  </span>
                                  <span className="mt-1 flex gap-1">
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
                      <p role="alert" className="mt-4 text-xs text-danger">
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
                      isDisabled={pending || !selectedUserId}
                      onPress={() => void submit()}
                    >
                      {pending ? (
                        <Spinner size="sm" aria-label={t('working')} />
                      ) : null}
                      {t('roleUsersAssignConfirm')}
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

function RevokeRoleFromUserDialog({
  binding,
  onRevoked,
  onReload,
  reloadPending,
}: {
  binding: RoleUserBinding
  onRevoked: () => void
  onReload: () => void
  reloadPending: boolean
}) {
  const t = useTranslator()
  const state = useOverlayState()
  const mutations = useRoleMutations()
  const [feedback, setFeedback] = useState<RbacFeedbackState | null>(null)
  const [pending, setPending] = useState(false)
  const submitting = useRef(false)
  const opened = useRef(false)

  useEffect(() => {
    if (state.isOpen) {
      opened.current = true
      return
    }
    if (!opened.current) return
    setFeedback(null)
    setPending(false)
  }, [state.isOpen])

  async function submit() {
    if (submitting.current) return
    submitting.current = true
    setPending(true)
    setFeedback(null)
    const input: RevokeUserRolesInput = {
      userId: binding.userId,
      roleIds: [binding.roleId],
      expectedUserVersion: binding.userVersion,
    }
    try {
      const result = await mutations.revokeUserRoles(input)
      const payload = result.data?.revokeUserRoles ?? null
      if (!payload) {
        setFeedback({
          errors: result.errors,
          failure: result.failure ?? {
            kind: 'invalid_response',
            code: 'missing_revoke_user_roles_payload',
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
      toast.success(t('roleUserRevokedToast'), {
        description: t('roleUserRevokedCommitted', {
          count: payload.revokedCount,
        }),
      })
      if (result.partial) toast.warning(t('rbacPartialMutationNote'))
      onRevoked()
    } catch {
      setFeedback({
        errors: [],
        failure: { kind: 'network', code: 'revoke_user_roles_request_failed' },
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
        subject={binding.user?.username ?? binding.userId}
        actions={[
          {
            id: 'remove',
            label: t('roleUsersRevokeAction'),
            onAction: state.open,
            danger: true,
            icon: <XCircle className="size-4" aria-hidden="true" />,
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
                    <Modal.Heading>{t('roleUsersRevokeTitle')}</Modal.Heading>
                  </Modal.Header>
                  <Modal.Body>
                    <p className="text-sm leading-6 text-muted">
                      {t('roleUsersRevokeDescription', {
                        user: binding.user?.username ?? binding.userId,
                      })}
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
                      isDisabled={pending}
                      onPress={() => void submit()}
                    >
                      {pending ? (
                        <Spinner size="sm" aria-label={t('working')} />
                      ) : null}
                      {t('roleUsersRevokeConfirm')}
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
