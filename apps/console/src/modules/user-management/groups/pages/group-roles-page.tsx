import { DataTable } from '@identity/ui/data-table'
import {
  Alert,
  Button,
  Checkbox,
  Chip,
  Modal,
  Pagination,
  Skeleton,
  Spinner,
  toast,
  useOverlayState,
} from '@heroui/react'
import { Link, useNavigate } from '@tanstack/react-router'
import { Pencil, Search } from 'lucide-react'
import { useEffect, useMemo, useRef, useState } from 'react'

import { AsyncState } from '#/components/async-state'
import { ErrorDetails } from '#/components/error-details'
import { RequestCorrelation } from '#/components/request-correlation'
import { StepUpPanel } from '#/components/step-up-panel'
import {
  ConsoleRolesDocument,
  type ConsoleGroupRolesQuery,
  type ConsoleGroupRolesQueryVariables,
  type ConsoleRolesQuery,
  type ConsoleRolesQueryVariables,
  type SetGroupRolesInput,
} from '#/gql/graphql'
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
  useGroupRoleMutations,
  useGroupRoles,
} from '#/modules/user-management/groups/hooks/use-group-roles'
import { resolveLocalizedText } from '#/modules/user-management/groups/lib/groups-search'
import type { RbacFeedbackState } from '#/modules/user-management/lib/rbac-errors'
import { useConsoleQuery } from '#/modules/user-management/lib/console-query'
import { cursorPage } from '#/modules/user-management/lib/cursor-page'
import { clearDraft, readDraft, writeDraft } from '#/lib/draft-storage'
import { rbacScope } from '#/modules/user-management/lib/rbac-scope'
import { RbacAccessRestricted } from '#/modules/user-management/roles/components/role-access'
import { BindingStatusChip } from '#/modules/user-management/roles/components/role-status'
import {
  UserSelectField,
  UserTextField,
} from '#/modules/user-management/users/components/user-form-fields'

const PAGE_SIZE = 5
const ROLE_PICKER_PAGE_SIZE = 5

type GroupNode = NonNullable<ConsoleGroupRolesQuery['group']>
type RelationStatus = 'any' | 'enabled' | 'disabled'

interface RoleEditDraft {
  roleIds: string[]
}

function roleEditDraftKey(groupId: string): string {
  return `identity.console.group-roles.${groupId}`
}

function readRoleEditDraft(groupId: string): RoleEditDraft | null {
  const stored = readDraft<unknown>(roleEditDraftKey(groupId))
  if (!stored || typeof stored !== 'object' || Array.isArray(stored))
    return null
  const value = stored as Record<string, unknown>
  if (!Array.isArray(value.roleIds)) return null
  return {
    roleIds: value.roleIds.filter((id): id is string => typeof id === 'string'),
  }
}

function sameRoleSet(
  left: ReadonlyArray<string>,
  right: ReadonlyArray<string>,
) {
  if (left.length !== right.length) return false
  const rightSet = new Set(right)
  return left.every((id) => rightSet.has(id))
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

export function GroupRolesPage({ groupId }: { groupId: string }) {
  const t = useTranslator()
  const { locale } = useLocale()
  const navigate = useNavigate()
  const workspace = useWorkspace()
  const scope = useMemo(
    () => rbacScope(workspace.data?.effectivePermissions),
    [workspace.data?.effectivePermissions],
  )
  const canRead = scope.groupsRead && scope.groupRolesRead
  const [status, setStatus] = useState<RelationStatus>('any')
  const [after, setAfter] = useState<string | undefined>()
  const [before, setBefore] = useState<string | undefined>()
  const [search, setSearch] = useState('')
  const [notice, setNotice] = useState<RbacNotice | null>(null)
  const pageState = nextPageState(setAfter, setBefore)

  const variables = useMemo<ConsoleGroupRolesQueryVariables | null>(
    () =>
      canRead
        ? {
            groupId,
            filter: status === 'any' ? {} : { enabled: status === 'enabled' },
            orderBy: 'ROLE_NAME_ASC',
            ...cursorPage(PAGE_SIZE, after, before),
            includeRole: scope.rolesRead,
          }
        : null,
    [after, before, canRead, groupId, scope.rolesRead, status],
  )
  const roles = useGroupRoles(variables)
  const group = roles.data?.group ?? null

  if (!canRead) {
    return (
      <ConsoleWorkspaceGate>
        <RbacAccessRestricted
          title={
            !scope.groupsRead ? 'groupsNoReadTitle' : 'groupRolesNoReadTitle'
          }
          description={
            !scope.groupsRead
              ? 'groupsNoReadDescription'
              : 'groupRolesNoReadDescription'
          }
          stepUp={
            !scope.groupsRead
              ? scope.groupsReadStepUp
              : scope.groupRolesReadStepUp
          }
          onBack={() => void navigate({ to: '/groups' })}
          backLabel="backToGroups"
        />
      </ConsoleWorkspaceGate>
    )
  }

  if (roles.status === 'error') {
    return (
      <ConsoleWorkspaceGate>
        {roles.stepUp ? (
          <StepUpPanel
            stepUp={roles.stepUp}
            hideDetails
            description={t('rbacStepUpDescription')}
            note={t('rbacStepUpNote')}
          />
        ) : (
          <AsyncState
            kind={roles.forbidden ? 'forbidden' : 'error'}
            title={t(failureTitleKey(roles.failure, roles.forbidden))}
            description={t(
              failureDescriptionKey(roles.failure, roles.forbidden),
            )}
            requestId={roles.requestId}
            traceId={roles.traceId}
            issues={roles.errors}
            onRetry={() => void roles.refresh()}
          />
        )}
      </ConsoleWorkspaceGate>
    )
  }

  if (roles.status === 'ready' && !group) {
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

  if (roles.status !== 'ready' || !group) {
    return (
      <ConsoleWorkspaceGate>
        <AsyncState kind="loading" title={t('loading')} />
      </ConsoleWorkspaceGate>
    )
  }

  const readyGroup = group
  const groupName =
    (resolveLocalizedText(readyGroup.names, locale) ?? readyGroup.name) ?? readyGroup.id
  const normalizedSearch = search.trim().toLowerCase()
  const edges = readyGroup.roles.edges.filter(({ node }) => {
    if (!normalizedSearch) return true
    const role = scope.rolesRead ? (node.role ?? null) : null
    const name = role
      ? (resolveLocalizedText(role.names, locale) ?? role.name ?? role.id)
      : ''
    return [name, node.roleId, node.id]
      .join(' ')
      .toLowerCase()
      .includes(normalizedSearch)
  })

  return (
    <ConsoleWorkspaceGate>
      <div className="space-y-4">
        {notice ? (
          <RbacNoticeAlert notice={notice} onDismiss={() => setNotice(null)} />
        ) : null}

        {scope.groupRolesWriteStepUp && !readyGroup.builtIn ? (
          <StepUpPanel
            stepUp={{ source: 'graphql', acrValues: 'aal2' }}
            hideDetails
            description={t('rbacStepUpDescription')}
            note={t('groupRolesWriteStepUpNote')}
          />
        ) : null}

        {readyGroup.builtIn ? (
          <Alert status="default">
            <Alert.Indicator />
            <Alert.Content>
              <Alert.Title>{t('groupRolesBuiltInTitle')}</Alert.Title>
              <Alert.Description>
                {t('groupRolesBuiltInDescription')}
              </Alert.Description>
            </Alert.Content>
          </Alert>
        ) : null}

        {!scope.rolesRead ? (
          <Alert status="warning">
            <Alert.Indicator />
            <Alert.Content>
              <Alert.Title>{t('groupRolesNoRoleReadTitle')}</Alert.Title>
              <Alert.Description>
                {t('groupRolesNoRoleReadDescription')}
              </Alert.Description>
              {!readyGroup.builtIn ? (
                <p className="mt-2 text-xs text-muted">
                  {t('groupRolesSelectionNoRolesRead')}
                </p>
              ) : null}
            </Alert.Content>
          </Alert>
        ) : null}

        {!readyGroup.builtIn &&
        !scope.groupRolesWriteReady &&
        !scope.groupRolesWriteStepUp ? (
          <Alert status="warning">
            <Alert.Indicator />
            <Alert.Content>
              <Alert.Title>{t('groupRolesNoWritePermission')}</Alert.Title>
              <Alert.Description>
                {t('groupRolesNoWriteDescription')}
              </Alert.Description>
            </Alert.Content>
          </Alert>
        ) : null}

        <section className="space-y-4">
          <header className="flex flex-col gap-3 py-2 sm:flex-row sm:items-end sm:justify-between">
            <div>
              <h2 className="text-base font-semibold">
                {t('groupRolesListTitle')}
              </h2>
              <p className="mt-1 text-sm text-muted">
                {t('groupRolesListDescription')}
              </p>
            </div>
            <div className="flex flex-wrap items-end gap-2">
              <div className="w-48">
                <UserTextField
                  name="group-role-search"
                  label={t('groupRolesSearchLabel')}
                  value={search}
                  onChange={setSearch}
                  placeholder={t('groupRolesSearchPlaceholder')}
                  maxLength={256}
                />
              </div>
              <div className="w-40">
                <UserSelectField
                  name="group-role-status"
                  label={t('groupRolesFilterStatusLabel')}
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
                    { id: 'any', label: t('groupRolesFilterAll') },
                    { id: 'enabled', label: t('groupRolesFilterActive') },
                    { id: 'disabled', label: t('groupRolesFilterRemoved') },
                  ]}
                />
              </div>
              {!readyGroup.builtIn &&
              scope.rolesRead &&
              scope.groupRolesWriteReady ? (
                <EditRolesDialog
                  groupId={readyGroup.id}
                  groupVersion={readyGroup.version}
                  groupName={groupName}
                  onSaved={(addedCount, removedCount) => {
                    setNotice({
                      kind: 'success',
                      title: t('groupRolesSavedToast'),
                      description: t('groupRolesSavedCommitted', {
                        addedCount,
                        removedCount,
                      }),
                    })
                    void roles.refresh()
                  }}
                  onReload={() => void roles.refresh()}
                  reloadPending={roles.refreshing}
                />
              ) : null}
            </div>
          </header>
          <div className="p-0">
            {roles.partial ? (
              <div className="p-3">
                <Alert status="warning">
                  <Alert.Indicator />
                  <Alert.Content>
                    <Alert.Title>{t('groupsPartialTitle')}</Alert.Title>
                    <Alert.Description>
                      {t('groupsPartialDescription')}
                    </Alert.Description>
                    <RequestCorrelation
                      requestId={roles.requestId}
                      traceId={roles.traceId}
                    />
                    <ErrorDetails issues={roles.errors} />
                  </Alert.Content>
                </Alert>
              </div>
            ) : null}
            {readyGroup.roles.edges.length === 0 ? (
              <div className="p-4">
                <AsyncState
                  kind="empty"
                  compact
                  title={
                    status === 'any'
                      ? t('groupRolesEmptyTitle')
                      : t('groupRolesEmptyFilteredTitle')
                  }
                  description={
                    status === 'any'
                      ? t('groupRolesEmptyDescription')
                      : t('groupRolesEmptyFilteredDescription')
                  }
                />
              </div>
            ) : edges.length === 0 ? (
              <div className="p-4">
                <AsyncState
                  kind="empty"
                  compact
                  title={t('groupRolesSearchNoMatches')}
                  description={t('groupRolesSearchDescription')}
                />
              </div>
            ) : (
              <DataTable
                label={t('groupRolesTableLabel')}
                minWidth={820}
                columns={[
                  {
                    id: 'groupRolesColumnRole',
                    label: t('groupRolesColumnRole'),
                    primary: true,
                  },
                  {
                    id: 'groupRolesColumnRelation',
                    label: t('groupRolesColumnRelation'),
                    primary: false,
                  },
                ]}
              >
                <DataTable.Body>
                  {edges.map(({ node }) => {
                    const role = scope.rolesRead ? (node.role ?? null) : null
                    const name = role
                      ? ((resolveLocalizedText(role.names, locale) ?? role.name) ??
                        role.name ??
                        role.id)
                      : null
                    return (
                      <DataTable.Row key={node.id} id={node.id}>
                        <DataTable.Cell>
                          <div className="min-w-56">
                            {role && name ? (
                              <>
                                <Link
                                  to="/roles/$roleId"
                                  params={{ roleId: role.id }}
                                  className="font-medium text-foreground underline-offset-4 hover:underline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-focus"
                                >
                                  {name}
                                </Link>
                                <div className="mt-1 flex flex-wrap gap-1">
                                  {role.builtIn ? (
                                    <Chip
                                      size="sm"
                                      variant="soft"
                                      color="accent"
                                    >
                                      <Chip.Label>
                                        {t('groupRolesBuiltInRoleLabel')}
                                      </Chip.Label>
                                    </Chip>
                                  ) : null}
                                  {!role.enabled ? (
                                    <Chip
                                      size="sm"
                                      variant="soft"
                                      color="warning"
                                    >
                                      <Chip.Label>
                                        {t('rolesDisabled')}
                                      </Chip.Label>
                                    </Chip>
                                  ) : null}
                                </div>
                              </>
                            ) : (
                              <>
                                <p className="break-all font-mono text-xs">
                                  {node.roleId}
                                </p>
                                <p className="mt-0.5 text-[11px] text-muted">
                                  {t('groupRolesRoleIdOnly')}
                                </p>
                              </>
                            )}
                          </div>
                        </DataTable.Cell>
                        <DataTable.Cell>
                          <BindingStatusChip
                            enabled={node.enabled}
                            revokedAt={node.revokedAt}
                            roleEnabled={role?.enabled}
                          />
                        </DataTable.Cell>
                      </DataTable.Row>
                    )
                  })}
                </DataTable.Body>
              </DataTable>
            )}
          </div>
          <footer className="border-t border-separator pt-4">
            <RolesPagination
              connection={readyGroup.roles}
              count={normalizedSearch ? edges.length : undefined}
              status={roles.status}
              onNext={pageState.next}
              onPrevious={pageState.previous}
            />
          </footer>
        </section>
      </div>
    </ConsoleWorkspaceGate>
  )
}

function RolesPagination({
  connection,
  count,
  status,
  onNext,
  onPrevious,
}: {
  connection: GroupNode['roles'] | null
  count?: number
  status: string
  onNext: (cursor: string | null) => void
  onPrevious: (cursor: string | null) => void
}) {
  const t = useTranslator()
  if (status !== 'ready' || !connection) return null
  return (
    <Pagination aria-label={t('groupRolesPagination')}>
      <Pagination.Summary>
        {t('groupRolesPageSummary', {
          count: count ?? connection.edges.length,
        })}
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

function EditRolesDialog({
  groupId,
  groupVersion,
  groupName,
  onSaved,
  onReload,
  reloadPending,
}: {
  groupId: string
  groupVersion: string
  groupName: string
  onSaved: (addedCount: number, removedCount: number) => void
  onReload: () => void
  reloadPending: boolean
}) {
  const t = useTranslator()
  const { locale } = useLocale()
  const state = useOverlayState()
  const mutations = useGroupRoleMutations()
  const draftKey = roleEditDraftKey(groupId)
  const [query, setQuery] = useState('')
  const [appliedQuery, setAppliedQuery] = useState('')
  const [after, setAfter] = useState<string | undefined>()
  const [before, setBefore] = useState<string | undefined>()
  const [selected, setSelected] = useState<Set<string>>(() => {
    const draft = readRoleEditDraft(groupId)
    return new Set(draft?.roleIds ?? [])
  })
  const hasStoredSelection = useRef(Boolean(readRoleEditDraft(groupId)))
  const [roleSnapshot, setRoleSnapshot] = useState<string[] | null>(null)
  const [snapshotStatus, setSnapshotStatus] = useState<
    'idle' | 'loading' | 'ready' | 'error'
  >('idle')
  const [snapshotFeedback, setSnapshotFeedback] =
    useState<RbacFeedbackState | null>(null)
  const [feedback, setFeedback] = useState<RbacFeedbackState | null>(null)
  const [localError, setLocalError] = useState<string | null>(null)
  const [pending, setPending] = useState(false)
  const submitting = useRef(false)
  const opened = useRef(false)
  const completed = useRef(false)
  const loadVersion = useRef(0)

  const roleVariables = useMemo<ConsoleRolesQueryVariables | null>(
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
  const catalog = useConsoleQuery<
    ConsoleRolesQuery,
    ConsoleRolesQueryVariables
  >(
    ConsoleRolesDocument,
    roleVariables,
    'ConsoleRoles',
    Boolean(roleVariables),
    'missing_role_connection',
  )

  useEffect(() => {
    if (!state.isOpen) return
    opened.current = true
    const version = loadVersion.current + 1
    loadVersion.current = version
    setSnapshotStatus('loading')
    setSnapshotFeedback(null)
    setFeedback(null)
    setLocalError(null)
    setPending(false)
    void mutations
      .loadActiveRoleIds(groupId)
      .then((snapshot) => {
        if (loadVersion.current !== version) return
        if (snapshot.failure || snapshot.partial) {
          setSnapshotStatus('error')
          setSnapshotFeedback({
            errors: snapshot.errors,
            failure: snapshot.failure ?? {
              kind: 'invalid_response',
              code: 'partial_group_role_snapshot',
              requestId: snapshot.requestId,
              traceId: snapshot.traceId,
            },
            stepUp: snapshot.stepUp,
            requestId: snapshot.requestId,
            traceId: snapshot.traceId,
            forbidden: snapshot.forbidden,
          })
          return
        }
        setRoleSnapshot(snapshot.roleIds)
        setSnapshotStatus('ready')
        if (!hasStoredSelection.current) {
          setSelected(new Set(snapshot.roleIds))
        }
      })
      .catch(() => {
        if (loadVersion.current !== version) return
        setSnapshotStatus('error')
        setSnapshotFeedback({
          errors: [],
          failure: {
            kind: 'network',
            code: 'group_role_snapshot_request_failed',
          },
          forbidden: false,
        })
      })
  }, [groupId, mutations, state.isOpen])

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
    setRoleSnapshot(null)
    setSnapshotStatus('idle')
    setSnapshotFeedback(null)
    setFeedback(null)
    setLocalError(null)
    setPending(false)
    completed.current = false
    loadVersion.current += 1
  }, [draftKey, state.isOpen])

  useEffect(() => {
    if (!state.isOpen || !hasStoredSelection.current) return
    writeDraft(draftKey, {
      roleIds: [...selected],
    } satisfies RoleEditDraft)
  }, [draftKey, selected, state.isOpen])

  function toggleRole(roleId: string, isSelected: boolean) {
    hasStoredSelection.current = true
    setSelected((current) => {
      const next = new Set(current)
      if (isSelected) next.add(roleId)
      else next.delete(roleId)
      return next
    })
    setLocalError(null)
    setFeedback(null)
  }

  async function reloadSnapshot() {
    const version = loadVersion.current + 1
    loadVersion.current = version
    setSnapshotStatus('loading')
    setSnapshotFeedback(null)
    const snapshot = await mutations.loadActiveRoleIds(groupId)
    if (loadVersion.current !== version) return
    if (snapshot.failure || snapshot.partial) {
      setSnapshotStatus('error')
      setSnapshotFeedback({
        errors: snapshot.errors,
        failure: snapshot.failure ?? {
          kind: 'invalid_response',
          code: 'partial_group_role_snapshot',
          requestId: snapshot.requestId,
          traceId: snapshot.traceId,
        },
        stepUp: snapshot.stepUp,
        requestId: snapshot.requestId,
        traceId: snapshot.traceId,
        forbidden: snapshot.forbidden,
      })
      return
    }
    setRoleSnapshot(snapshot.roleIds)
    setSnapshotStatus('ready')
    setSelected(new Set(snapshot.roleIds))
    hasStoredSelection.current = true
  }

  async function submit() {
    if (submitting.current || snapshotStatus !== 'ready') return
    if (!groupVersion) {
      setLocalError(t('groupsVersionUnavailable'))
      return
    }
    submitting.current = true
    setPending(true)
    setFeedback(null)
    setLocalError(null)
    const input: SetGroupRolesInput = {
      groupId,
      roleIds: [...selected],
      expectedVersion: groupVersion,
    }
    try {
      const result = await mutations.setRoles(input)
      const payload = result.data?.setGroupRoles ?? null
      if (!payload) {
        setFeedback({
          errors: result.errors,
          failure: result.failure ?? {
            kind: 'invalid_response',
            code: 'missing_set_group_roles_payload',
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
      toast.success(t('groupRolesSavedToast'), {
        description: t('groupRolesSavedCommitted', {
          addedCount: payload.addedCount,
          removedCount: payload.removedCount,
        }),
      })
      if (result.partial) toast.warning(t('rbacPartialMutationNote'))
      onSaved(payload.addedCount, payload.removedCount)
    } catch {
      setFeedback({
        errors: [],
        failure: { kind: 'network', code: 'set_group_roles_request_failed' },
        forbidden: false,
      })
    } finally {
      submitting.current = false
      setPending(false)
    }
  }

  const connection = catalog.data?.roles ?? null
  const roleEdges = connection?.edges ?? []
  const changes =
    roleSnapshot !== null && !sameRoleSet([...selected], roleSnapshot)
  const canSave =
    snapshotStatus === 'ready' && !pending && Boolean(groupVersion) && changes

  return (
    <>
      <Button onPress={state.open} isDisabled={!groupVersion}>
        <Pencil className="size-4" aria-hidden="true" />
        {t('groupRolesEditAction')}
      </Button>
      <Modal state={state}>
        <Modal.Backdrop isDismissable={!pending}>
          <Modal.Container size="lg" scroll="inside">
            <Modal.Dialog className="w-full max-w-3xl">
              {({ close }) => (
                <>
                  <Modal.CloseTrigger
                    aria-label={t('close')}
                    isDisabled={pending}
                  />
                  <Modal.Header>
                    <Modal.Heading>{t('groupRolesEditTitle')}</Modal.Heading>
                  </Modal.Header>
                  <Modal.Body className="flex min-h-0 flex-col gap-3 overflow-hidden">
                    <p className="text-sm leading-5 text-muted">
                      {t('groupRolesEditDescription', { group: groupName })}
                    </p>
                    <p className="text-xs leading-5 text-muted">
                      {t('groupRolesEditHint')}
                    </p>

                    {snapshotStatus === 'loading' ? (
                      <div
                        className="flex items-center gap-2 rounded-field border border-border p-3 text-sm"
                        role="status"
                      >
                        <Spinner size="sm" aria-label={t('loading')} />
                        {t('groupRolesCurrentLoading')}
                      </div>
                    ) : null}

                    {snapshotStatus === 'error' && snapshotFeedback ? (
                      <div className="space-y-2">
                        <RbacMutationFeedback
                          feedback={snapshotFeedback}
                          onReload={() => void reloadSnapshot()}
                        />
                        <Button
                          size="sm"
                          variant="secondary"
                          onPress={() => void reloadSnapshot()}
                        >
                          {t('groupRolesCurrentReload')}
                        </Button>
                      </div>
                    ) : null}

                    <form
                      className="collection-filter-controls flex items-end gap-2"
                      onSubmit={(event) => {
                        event.preventDefault()
                        setAppliedQuery(query.trim())
                        setAfter(undefined)
                        setBefore(undefined)
                      }}
                    >
                      <div className="min-w-0 flex-1">
                        <UserTextField
                          name="group-role-catalog-search"
                          label={t('groupRolesCatalogSearchLabel')}
                          value={query}
                          onChange={setQuery}
                          placeholder={t('groupRolesCatalogSearchPlaceholder')}
                          maxLength={256}
                        />
                      </div>
                      <Button type="submit" size="sm">
                        <Search className="size-4" aria-hidden="true" />
                        {t('roleUsersSearchAction')}
                      </Button>
                    </form>

                    <div
                      className="min-h-40 flex-1 overflow-y-auto rounded-field border border-border"
                      role="region"
                      aria-label={t('groupRolesCatalogLabel')}
                    >
                      {catalog.status === 'error' ? (
                        <div className="p-3">
                          <AsyncState
                            kind={catalog.forbidden ? 'forbidden' : 'error'}
                            compact
                            title={t(
                              failureTitleKey(
                                catalog.failure,
                                catalog.forbidden,
                              ),
                            )}
                            description={t(
                              failureDescriptionKey(
                                catalog.failure,
                                catalog.forbidden,
                              ),
                            )}
                            requestId={catalog.requestId}
                            traceId={catalog.traceId}
                            issues={catalog.errors}
                            onRetry={() => void catalog.refresh()}
                          />
                        </div>
                      ) : catalog.status !== 'ready' ? (
                        <div
                          className="space-y-2 p-3"
                          role="status"
                          aria-label={t('groupRolesCatalogLoading')}
                        >
                          <span className="sr-only">
                            {t('groupRolesCatalogLoading')}
                          </span>
                          {Array.from({ length: 4 }, (_, index) => (
                            <Skeleton
                              key={index}
                              className="h-14 w-full rounded-field"
                            />
                          ))}
                        </div>
                      ) : roleEdges.length === 0 ? (
                        <div className="p-3">
                          <AsyncState
                            kind="empty"
                            compact
                            title={t('groupRolesCatalogEmpty')}
                            description={t('groupRolesCatalogEmptyDescription')}
                          />
                        </div>
                      ) : (
                        <ul className="divide-y divide-separator">
                          {roleEdges.map(({ node }) => {
                            const name =
                              (resolveLocalizedText(node.names, locale) ?? node.name) ??
                              node.name ??
                              node.id
                            return (
                              <li key={node.id}>
                                <Checkbox
                                  className="w-full"
                                  isSelected={selected.has(node.id)}
                                  onChange={(isSelected) =>
                                    toggleRole(node.id, isSelected)
                                  }
                                >
                                  <Checkbox.Content className="min-h-14 w-full items-center gap-3 px-3 py-2 text-start">
                                    <Checkbox.Control>
                                      <Checkbox.Indicator />
                                    </Checkbox.Control>
                                    <span className="min-w-0 flex-1">
                                      <span className="flex flex-wrap items-center gap-2">
                                        <span className="text-sm font-medium">
                                          {name}
                                        </span>
                                        {node.builtIn ? (
                                          <Chip
                                            size="sm"
                                            variant="soft"
                                            color="accent"
                                          >
                                            <Chip.Label>
                                              {t('groupRolesBuiltInRoleLabel')}
                                            </Chip.Label>
                                          </Chip>
                                        ) : null}
                                        {!node.enabled ? (
                                          <Chip
                                            size="sm"
                                            variant="soft"
                                            color="warning"
                                          >
                                            <Chip.Label>
                                              {t('rolesDisabled')}
                                            </Chip.Label>
                                          </Chip>
                                        ) : null}
                                      </span>
                                    </span>
                                  </Checkbox.Content>
                                </Checkbox>
                              </li>
                            )
                          })}
                        </ul>
                      )}
                    </div>

                    {connection ? (
                      <div className="flex items-center justify-between gap-2">
                        <span className="text-xs text-muted">
                          {t('groupRolesSelectedCount', {
                            count: selected.size,
                          })}
                        </span>
                        <div className="flex gap-2">
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
                      </div>
                    ) : null}

                    {catalog.partial ? (
                      <Alert status="warning">
                        <Alert.Indicator />
                        <Alert.Content>
                          <Alert.Title>{t('rolesPartialTitle')}</Alert.Title>
                          <Alert.Description>
                            {t('rolesPartialDescription')}
                          </Alert.Description>
                          <RequestCorrelation
                            requestId={catalog.requestId}
                            traceId={catalog.traceId}
                          />
                          <ErrorDetails issues={catalog.errors} />
                        </Alert.Content>
                      </Alert>
                    ) : null}

                    {snapshotStatus === 'ready' && !changes ? (
                      <p className="text-xs text-muted">
                        {t('groupRolesNoChanges')}
                      </p>
                    ) : null}

                    {localError ? (
                      <p role="alert" className="text-xs text-danger">
                        {localError}
                      </p>
                    ) : null}
                    {feedback ? (
                      <RbacMutationFeedback
                        feedback={feedback}
                        onReload={() => {
                          setFeedback(null)
                          void reloadSnapshot()
                          onReload()
                        }}
                        reloadPending={reloadPending}
                      />
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
                    <Button isDisabled={!canSave} onPress={() => void submit()}>
                      {pending ? (
                        <Spinner size="sm" aria-label={t('working')} />
                      ) : null}
                      {t('groupRolesSaveAction')}
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
