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
import { useNavigate } from '@tanstack/react-router'
import { Search, ShieldPlus, XCircle } from 'lucide-react'
import { useEffect, useMemo, useRef, useState } from 'react'

import { AsyncState } from '#/components/async-state'
import { ErrorDetails } from '#/components/error-details'
import { RequestCorrelation } from '#/components/request-correlation'
import { StepUpPanel } from '#/components/step-up-panel'
import {
  ConsoleRolesDocument,
  ConsoleUserRolesDocument,
  type ConsoleRolesQuery,
  type ConsoleRolesQueryVariables,
  type ConsoleUserRolesQuery,
  type ConsoleUserRolesQueryVariables,
  type RevokeUserRolesInput,
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
  RbacMutationFeedback,
  RbacNoticeAlert,
  type RbacNotice,
} from '#/modules/user-management/components/rbac-feedback'
import { ConsoleWorkspaceGate } from '#/modules/user-management/components/workspace-gate'
import { resolveLocalizedText } from '#/modules/user-management/groups/lib/groups-search'
import { RbacAccessRestricted } from '#/modules/user-management/roles/components/role-access'
import { BindingStatusChip } from '#/modules/user-management/roles/components/role-status'
import { useRoleMutations } from '#/modules/user-management/roles/hooks/role-mutations'
import { useConsoleQuery } from '#/modules/user-management/lib/console-query'
import { cursorPage } from '#/modules/user-management/lib/cursor-page'
import { clearDraft, readDraft, writeDraft } from '#/lib/draft-storage'
import type { RbacFeedbackState } from '#/modules/user-management/lib/rbac-errors'
import { rbacScope } from '#/modules/user-management/lib/rbac-scope'
import { useUserDetailContext } from '#/modules/user-management/users/components/user-detail-context'
import {
  UserSelectField,
  UserTextField,
} from '#/modules/user-management/users/components/user-form-fields'

const PAGE_SIZE = 10
const ROLE_PICKER_PAGE_SIZE = 10

interface AssignRolesDraft {
  roleIds: string[]
}

function assignRolesDraftKey(userId: string): string {
  return `identity.console.user-role-assign.${userId}`
}

function readAssignRolesDraft(userId: string): AssignRolesDraft | null {
  const stored = readDraft<unknown>(assignRolesDraftKey(userId))
  if (!stored || typeof stored !== 'object' || Array.isArray(stored)) {
    return null
  }
  const value = stored as Record<string, unknown>
  if (!Array.isArray(value.roleIds)) return null
  return {
    roleIds: value.roleIds.filter((id): id is string => typeof id === 'string'),
  }
}

type UserBinding = ConsoleUserRolesQuery['userRoles']['edges'][number]['node']
type BindingStatus = 'any' | 'active' | 'revoked'

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
            stepUp={scope.usersReadStepUp}
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
            stepUp={scope.assignmentReadStepUp}
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
          {scope.assignmentWriteStepUp ? (
            <StepUpPanel
              stepUp={{ source: 'graphql', acrValues: 'aal2' }}
              hideDetails
              description={t('rbacStepUpDescription')}
              note={t('userRolesStepUpNote')}
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
                scope.assignmentWriteReady &&
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
                ) : scope.assignmentWriteReady && scope.rolesRead ? (
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
                <Pagination aria-label={t('userRolesPagination')}>
                  <Pagination.Summary>
                    {t('rolesPageSummary', { count: connection.edges.length })}
                  </Pagination.Summary>
                  <Pagination.Content>
                    <Pagination.Item>
                      <Pagination.Previous
                        isDisabled={!connection.pageInfo.hasPreviousPage}
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
                        isDisabled={!connection.pageInfo.hasNextPage}
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
                    scope.assignmentWriteReady ? (
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

function AssignRolesDialog({
  userId,
  username,
  expectedUserVersion,
  onAssigned,
  onReload,
  reloadPending,
}: {
  userId: string
  username: string
  expectedUserVersion: string
  onAssigned: () => void
  onReload: () => void
  reloadPending: boolean
}) {
  const t = useTranslator()
  const { locale } = useLocale()
  const state = useOverlayState()
  const mutations = useRoleMutations()
  const draftKey = assignRolesDraftKey(userId)
  const [query, setQuery] = useState('')
  const [appliedQuery, setAppliedQuery] = useState('')
  const [after, setAfter] = useState<string | undefined>()
  const [before, setBefore] = useState<string | undefined>()
  const [selected, setSelected] = useState<Set<string>>(
    () => new Set(readAssignRolesDraft(userId)?.roleIds ?? []),
  )
  const hasStoredSelection = useRef(Boolean(readAssignRolesDraft(userId)))
  const [feedback, setFeedback] = useState<RbacFeedbackState | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [pending, setPending] = useState(false)
  const submitting = useRef(false)
  const opened = useRef(false)
  const completed = useRef(false)

  const variables = useMemo<ConsoleRolesQueryVariables | null>(
    () =>
      state.isOpen
        ? {
            filter: appliedQuery ? { query: appliedQuery } : {},
            orderBy: 'NAME_ASC',
            ...cursorPage(ROLE_PICKER_PAGE_SIZE, after, before),
          }
        : null,
    [after, appliedQuery, before, state.isOpen],
  )
  const roles = useConsoleQuery<ConsoleRolesQuery, ConsoleRolesQueryVariables>(
    ConsoleRolesDocument,
    variables,
    'ConsoleRoles',
    Boolean(variables),
    'missing_role_connection',
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
    setSelected(new Set())
    hasStoredSelection.current = false
    setFeedback(null)
    setError(null)
    setPending(false)
    completed.current = false
  }, [draftKey, state.isOpen])

  useEffect(() => {
    if (!state.isOpen || !hasStoredSelection.current) return
    writeDraft(draftKey, {
      roleIds: [...selected],
    } satisfies AssignRolesDraft)
  }, [draftKey, selected, state.isOpen])

  async function submit() {
    if (submitting.current) return
    if (selected.size === 0) {
      setError(t('userRolesSelectRoleRequired'))
      return
    }
    if (!expectedUserVersion) {
      setFeedback({
        errors: [],
        failure: {
          kind: 'invalid_response',
          code: 'missing_user_version',
        },
        forbidden: false,
      })
      return
    }
    submitting.current = true
    setPending(true)
    setFeedback(null)
    setError(null)
    try {
      const result = await mutations.assignUserRoles({
        userId,
        roleIds: [...selected],
        expectedUserVersion,
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
      completed.current = true
      clearDraft(draftKey)
      state.close()
      toast.success(t('userRolesAssignedToast'), {
        description: t('userRolesAssignedCommitted', {
          count: payload.createdCount,
        }),
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

  const connection = roles.data?.roles ?? null
  const edges = connection?.edges ?? []

  return (
    <>
      <Button onPress={state.open}>
        <ShieldPlus className="size-4" aria-hidden="true" />
        {t('userRolesAssignAction')}
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
                    <Modal.Heading>{t('userRolesAssignTitle')}</Modal.Heading>
                  </Modal.Header>
                  <Modal.Body>
                    <p className="text-sm leading-6 text-muted">
                      {t('userRolesAssignDescription', { user: username })}
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
                        name="assign-role-search"
                        label={t('userRolesSearchRoles')}
                        value={query}
                        onChange={setQuery}
                        maxLength={256}
                      />
                      <Button type="submit">
                        <Search className="size-4" aria-hidden="true" />
                        {t('userRolesSearchAction')}
                      </Button>
                    </form>
                    <div className="mt-4 max-h-72 overflow-y-auto rounded-field border border-border">
                      {roles.status === 'error' ? (
                        <div className="p-3">
                          <AsyncState
                            kind={roles.forbidden ? 'forbidden' : 'error'}
                            compact
                            title={t(
                              failureTitleKey(roles.failure, roles.forbidden),
                            )}
                            description={t(
                              failureDescriptionKey(
                                roles.failure,
                                roles.forbidden,
                              ),
                            )}
                            requestId={roles.requestId}
                            traceId={roles.traceId}
                            issues={roles.errors}
                            onRetry={() => void roles.refresh()}
                          />
                        </div>
                      ) : roles.status !== 'ready' ? (
                        <div
                          className="space-y-2 p-3"
                          role="status"
                          aria-label={t('loading')}
                        >
                          <Skeleton className="h-12 w-full" />
                          <Skeleton className="h-12 w-full" />
                        </div>
                      ) : edges.length === 0 ? (
                        <p className="p-4 text-sm text-muted">
                          {t('userRolesNoCandidates')}
                        </p>
                      ) : (
                        <ul className="divide-y divide-separator">
                          {edges.map(({ node }) => (
                            <li key={node.id}>
                              <label className="flex cursor-pointer items-start gap-3 p-3 hover:bg-surface-secondary">
                                <input
                                  type="checkbox"
                                  className="mt-1 size-4"
                                  checked={selected.has(node.id)}
                                  onChange={() => {
                                    hasStoredSelection.current = true
                                    setSelected((current) => {
                                      const next = new Set(current)
                                      if (next.has(node.id))
                                        next.delete(node.id)
                                      else next.add(node.id)
                                      return next
                                    })
                                  }}
                                />
                                <span className="min-w-0">
                                  <span className="block text-sm font-medium">
                                    {resolveLocalizedText(node.names, locale) ??
                                      node.name ??
                                      node.name ??
                                      node.id}
                                  </span>
                                  {!node.enabled ? (
                                    <Chip
                                      size="sm"
                                      variant="soft"
                                      color="default"
                                      className="mt-1"
                                    >
                                      <Chip.Label>
                                        {t('rolesDisabled')}
                                      </Chip.Label>
                                    </Chip>
                                  ) : null}
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
                            if (connection.pageInfo.startCursor) {
                              setBefore(connection.pageInfo.startCursor)
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
                            if (connection.pageInfo.endCursor) {
                              setAfter(connection.pageInfo.endCursor)
                              setBefore(undefined)
                            }
                          }}
                        >
                          {t('nextPage')}
                        </Button>
                      </div>
                    ) : null}
                    {error ? (
                      <p role="alert" className="mt-3 text-sm text-danger">
                        {error}
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
                      isDisabled={pending || selected.size === 0}
                      onPress={() => void submit()}
                    >
                      {pending ? (
                        <Spinner size="sm" aria-label={t('working')} />
                      ) : null}
                      {t('userRolesAssignConfirm')}
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

function RevokeBindingDialog({
  binding,
  onRevoked,
  onReload,
  reloadPending,
}: {
  binding: UserBinding
  onRevoked: () => void
  onReload: () => void
  reloadPending: boolean
}) {
  const t = useTranslator()
  const { locale } = useLocale()
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
      toast.success(t('userRolesRevokedToast'), {
        description: t('userRolesRevokedCommitted', {
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
        subject={
          binding.role
            ? (resolveLocalizedText(binding.role.names, locale) ??
              binding.role.name ??
              binding.role.id)
            : binding.roleId
        }
        actions={[
          {
            id: 'remove',
            label: t('userRolesRevokeAction'),
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
                    <Modal.Heading>{t('userRolesRevokeTitle')}</Modal.Heading>
                  </Modal.Header>
                  <Modal.Body>
                    <p className="text-sm leading-6 text-muted">
                      {t('userRolesRevokeDescription', {
                        role: binding.role
                          ? (resolveLocalizedText(binding.role.names, locale) ??
                            binding.role.name ??
                            binding.role.id)
                          : binding.roleId,
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
                      {t('userRolesRevokeConfirm')}
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
