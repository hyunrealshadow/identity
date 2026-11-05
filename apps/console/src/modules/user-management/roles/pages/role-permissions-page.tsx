import { useRoleDetailContext } from '../components/role-detail-context'
import {
  Alert,
  Button,
  Chip,
  Skeleton,
  Spinner,
  toast,
  useOverlayState,
} from '@heroui/react'
import { useNavigate } from '@tanstack/react-router'
import { Check, Save } from 'lucide-react'
import { useEffect, useMemo, useRef, useState } from 'react'

import { UserSelectField } from '#/modules/user-management/users/components/user-form-fields'
import { AsyncState } from '#/components/async-state'
import { ConfirmationDialog } from '#/components/confirmation-dialog'
import { ErrorDetails } from '#/components/error-details'
import { StepUpPanel } from '#/components/step-up-panel'
import { type SetRolePermissionsInput } from '#/generated/graphql'
import {
  failureDescriptionKey,
  failureTitleKey,
} from '#/lib/graphql/presentation'
import { useLocale, useTranslator, type MessageKey } from '#/lib/i18n'
import { useWorkspace } from '#/lib/workspace'
import { RbacMutationFeedback } from '#/modules/user-management/components/rbac-feedback'
import { ConsoleWorkspaceGate } from '#/modules/user-management/components/workspace-gate'
import { PermissionPickerDialog } from '#/modules/user-management/roles/components/permission-picker-dialog'
import { RbacAccessRestricted } from '#/modules/user-management/roles/components/role-access'
import { RolePermissionTable } from '#/modules/user-management/roles/components/role-permission-table'
import { useRoleMembership } from '#/modules/user-management/roles/hooks/use-role-membership'
import { useRoleMutations } from '#/modules/user-management/roles/hooks/role-mutations'
import {
  roleDisplayName,
  roleIsBuiltIn,
  withRoleDisplayFields,
} from '#/modules/user-management/roles/lib/role-localization'
import {
  initialPermissionSelection,
  rolePermissionSubmitAvailability,
  selectionDiff,
  togglePermission,
  type PermissionMembershipState,
  type StagedPermission,
} from '#/modules/user-management/roles/lib/permission-selection'

import { clearDraft, readDraft, writeDraft } from '#/lib/draft-storage'
import { type RbacFeedbackState as FeedbackState } from '#/modules/user-management/lib/rbac-errors'
import { rbacScope } from '#/modules/user-management/lib/rbac-scope'

function permissionDraftKey(roleId: string): string {
  return `identity.console.role-permissions.${roleId}.draft`
}

interface PermissionDraft {
  membershipSignature: string
  selected: string[]
  staged: StagedPermission[]
}

function isStagedPermission(value: unknown): value is StagedPermission {
  if (!value || typeof value !== 'object') return false
  const item = value as Record<string, unknown>
  return (
    typeof item.id === 'string' &&
    typeof item.code === 'string' &&
    (item.description === null || typeof item.description === 'string') &&
    typeof item.resourceId === 'string' &&
    (item.resourceName === null || typeof item.resourceName === 'string') &&
    (item.resourceUri === null || typeof item.resourceUri === 'string') &&
    typeof item.enabled === 'boolean'
  )
}

function readPermissionDraft(roleId: string): PermissionDraft | null {
  const stored = readDraft<unknown>(permissionDraftKey(roleId))
  if (!stored || typeof stored !== 'object' || Array.isArray(stored)) {
    return null
  }
  const value = stored as Record<string, unknown>
  return {
    membershipSignature:
      typeof value.membershipSignature === 'string'
        ? value.membershipSignature
        : '',
    selected: Array.isArray(value.selected)
      ? value.selected.filter(
          (item): item is string => typeof item === 'string',
        )
      : [],
    staged: Array.isArray(value.staged)
      ? value.staged.filter(isStagedPermission)
      : [],
  }
}

export function RolePermissionsPage({ roleId }: { roleId: string }) {
  const t = useTranslator()
  const { locale } = useLocale()
  const navigate = useNavigate()
  const workspace = useWorkspace()
  const scope = useMemo(
    () => rbacScope(workspace.data?.effectivePermissions),
    [workspace.data?.effectivePermissions],
  )
  const roleQuery = useRoleDetailContext()
  const membership = useRoleMembership(
    roleId,
    Boolean(scope.rolesRead && scope.permissionRead),
    scope.resourcesRead,
  )
  const mutations = useRoleMutations()
  const confirmState = useOverlayState()
  const [selected, setSelected] = useState<Set<string>>(new Set())
  const [initial, setInitial] = useState<Set<string>>(new Set())
  const [staged, setStaged] = useState<Map<string, StagedPermission>>(new Map())
  const [feedback, setFeedback] = useState<FeedbackState | null>(null)
  const [resourceFilter, setResourceFilter] = useState('all')
  const [pending, setPending] = useState(false)
  const [notice, setNotice] = useState<string | null>(null)
  const [restoredSignature, setRestoredSignature] = useState<string | null>(
    null,
  )
  const submitting = useRef(false)
  const lastMembershipSignature = useRef<string | undefined>(undefined)

  const membershipSignature = `${membership.status}:${membership.loadedPages}:${membership.hasNextPage}:${[...membership.ids].sort().join(',')}`
  useEffect(() => {
    if (
      membership.status !== 'ready' ||
      membership.hasNextPage ||
      membership.loadedPages < 1
    ) {
      return
    }
    if (lastMembershipSignature.current === membershipSignature) return
    lastMembershipSignature.current = membershipSignature
    setRestoredSignature(null)
    const nextInitial = initialPermissionSelection(membership)
    setInitial(nextInitial)
    const stored = readPermissionDraft(roleId)
    if (stored && stored.membershipSignature === membershipSignature) {
      const nextStaged = new Map<string, StagedPermission>()
      for (const item of stored.staged) nextStaged.set(item.id, item)
      const allowed = new Set<string>([...nextInitial, ...nextStaged.keys()])
      setStaged(nextStaged)
      setSelected(
        new Set(
          stored.selected.filter((permissionId) => allowed.has(permissionId)),
        ),
      )
    } else {
      setStaged(new Map())
      setSelected(new Set(nextInitial))
    }
    setRestoredSignature(membershipSignature)
  }, [membership, membershipSignature, roleId])

  useEffect(() => {
    if (
      restoredSignature !== membershipSignature ||
      membership.status !== 'ready' ||
      membership.hasNextPage ||
      lastMembershipSignature.current !== membershipSignature
    ) {
      return
    }
    writeDraft(permissionDraftKey(roleId), {
      membershipSignature,
      selected: [...selected],
      staged: [...staged.values()],
    } satisfies PermissionDraft)
  }, [
    membership.hasNextPage,
    membership.status,
    membershipSignature,
    restoredSignature,
    roleId,
    selected,
    staged,
  ])

  const role = roleQuery.data?.role ?? null
  const membershipForSubmit: PermissionMembershipState = {
    status: membership.status,
    ids: membership.ids,
    loadedPages: membership.loadedPages,
    hasNextPage: membership.hasNextPage,
  }
  const availability = rolePermissionSubmitAvailability({
    membership: membershipForSubmit,
    catalogStatus: 'ready',
    initial,
    selected,
  })
  const diff = selectionDiff(initial, selected)
  const hasChanges = diff.added.length > 0 || diff.removed.length > 0
  const pendingAdditions = useMemo(
    () =>
      new Set(
        [...selected].filter((permissionId) => !initial.has(permissionId)),
      ),
    [initial, selected],
  )
  const localizedRole = role ? withRoleDisplayFields(role) : null
  const builtIn = localizedRole ? roleIsBuiltIn(localizedRole) : false

  const canWrite = !builtIn && scope.rolesWrite && Boolean(role?.version)
  const resourceOptions = useMemo(
    () => [
      ...new Map([
        ...membership.items
          .filter((item) => item.resourceId)
          .map(
            (item) =>
              [
                item.resourceId!,
                {
                  id: item.resourceId!,
                  label:
                    item.resource?.name ??
                    item.resource?.uri ??
                    t('rbacApiResource'),
                },
              ] as const,
          ),
        ...[...staged.values()].map(
          (item) =>
            [
              item.resourceId,
              {
                id: item.resourceId,
                label:
                  item.resourceName ?? item.resourceUri ?? t('rbacApiResource'),
              },
            ] as const,
        ),
      ]).values(),
    ],
    [membership.items, staged, t],
  )
  const selectedDisabledItems = membership.items.filter(
    (item) => !item.enabled && selected.has(item.id),
  )

  if (!scope.rolesRead || !scope.permissionRead) {
    return (
      <ConsoleWorkspaceGate>
        <RbacAccessRestricted
          title={
            !scope.rolesRead
              ? 'rolesNoReadTitle'
              : 'rolePermissionsNoCatalogTitle'
          }
          description={
            !scope.rolesRead
              ? 'rolesNoReadDescription'
              : 'rolePermissionsNoCatalogDescription'
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
        <AsyncState
          kind="notFound"
          title={t('notFoundTitle')}
          description={t('notFoundDescription')}
        />
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

  function submit() {
    if (!availability.allowed || !role || builtIn || submitting.current) return
    confirmState.close()
    submitting.current = true
    setPending(true)
    setFeedback(null)
    const input: SetRolePermissionsInput = {
      roleId: role.id,
      permissionIds: [...selected],
      expectedVersion: role.version,
    }
    clearDraft(permissionDraftKey(roleId))
    void mutations
      .setPermissions(input)
      .then(async (result) => {
        const payload = result.data?.setRolePermissions ?? null
        if (!payload) {
          setFeedback({
            errors: result.errors,
            failure: result.failure ?? {
              kind: 'invalid_response',
              code: 'missing_set_role_permissions_payload',
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
        toast.success(t('rolePermissionsSavedToast'), {
          description: t('rolePermissionsSavedDescription'),
        })
        if (result.partial) toast.warning(t('rbacPartialMutationNote'))
        setNotice(t('rolePermissionsReloadHint'))
        await Promise.all([roleQuery.refresh(), membership.reload()])
      })
      .catch(() => {
        setFeedback({
          errors: [],
          failure: {
            kind: 'network',
            code: 'set_role_permissions_request_failed',
          },
          forbidden: false,
        })
      })
      .finally(() => {
        submitting.current = false
        setPending(false)
      })
  }

  async function reloadConflict() {
    setFeedback(null)
    lastMembershipSignature.current = undefined
    await Promise.all([roleQuery.refresh(), membership.reload()])
  }

  function applyPickerSelection(ids: string[], metadata: StagedPermission[]) {
    const additions = new Set(ids)
    setSelected((current) => {
      const next = new Set(current)
      for (const permissionId of current) {
        if (!initial.has(permissionId) && !additions.has(permissionId)) {
          next.delete(permissionId)
        }
      }
      for (const permissionId of ids) next.add(permissionId)
      return next
    })
    setStaged((current) => {
      const next = new Map(current)
      for (const item of metadata) next.set(item.id, item)
      return next
    })
    setFeedback(null)
  }

  function resetSelection() {
    setSelected(new Set(initial))
    setStaged(new Map())
    setFeedback(null)
  }

  return (
    <ConsoleWorkspaceGate>
      <div className="space-y-4">
        {notice ? (
          <Alert status="success">
            <Alert.Indicator />
            <Alert.Content>
              <Alert.Title>{t('rolePermissionsSavedTitle')}</Alert.Title>
              <Alert.Description>{notice}</Alert.Description>
            </Alert.Content>
          </Alert>
        ) : null}

        {membership.stepUp ? (
          <StepUpPanel
            stepUp={membership.stepUp}
            hideDetails
            description={t('rbacStepUpDescription')}
            note={t('rbacStepUpNote')}
          />
        ) : null}
        {membership.status === 'error' ? (
          <AsyncState
            kind={membership.forbidden ? 'forbidden' : 'error'}
            title={t('roleMembershipLoadFailedTitle')}
            description={t('roleMembershipLoadFailedDescription')}
            requestId={membership.requestId}
            traceId={membership.traceId}
            issues={membership.errors}
            onRetry={() => {
              lastMembershipSignature.current = undefined
              void membership.reload()
            }}
          />
        ) : null}
        {membership.status === 'ready' && membership.errors.length > 0 ? (
          <Alert status="warning">
            <Alert.Indicator />
            <Alert.Content>
              <Alert.Title>{t('rolesPartialTitle')}</Alert.Title>
              <Alert.Description>
                {t('rolesPartialDescription')}
              </Alert.Description>
              <ErrorDetails issues={membership.errors} />
            </Alert.Content>
          </Alert>
        ) : null}

        {feedback ? (
          <RbacMutationFeedback
            feedback={feedback}
            onReload={() => void reloadConflict()}
            reloadPending={
              roleQuery.refreshing || membership.status === 'loading'
            }
          />
        ) : null}

        <section className="space-y-4">
          <div
            className="flex flex-wrap items-center justify-between gap-3 py-2"
            role="toolbar"
            aria-label={t('rolePermissionsToolbarLabel')}
          >
            <div className="w-full max-w-xl">
              <UserSelectField
                name="role-api-resource"
                label={t('rbacApiResource')}
                value={resourceFilter}
                onChange={setResourceFilter}
                options={[
                  { id: 'all', label: t('rbacAllApis') },
                  ...resourceOptions,
                ]}
              />
            </div>
            {builtIn ? null : (
              <PermissionPickerDialog
                subjectName={roleDisplayName(withRoleDisplayFields(role), locale)}
                assignedIds={initial}
                initialSelected={pendingAdditions}
                initialMetadata={staged}
                permissionRead={scope.permissionRead}
                resourcesRead={scope.resourcesRead}
                disabled={
                  !canWrite ||
                  pending ||
                  membership.status !== 'ready' ||
                  membership.hasNextPage
                }
                onApply={applyPickerSelection}
              />
            )}
          </div>
          <div className="p-0">
            {membership.status === 'error' ? null : membership.status !==
              'ready' ? (
              <div
                className="space-y-2 p-4"
                role="status"
                aria-label={t('roleMembershipLoading')}
              >
                <span className="sr-only">{t('roleMembershipLoading')}</span>
                {Array.from({ length: 4 }, (_, index) => (
                  <Skeleton key={index} className="h-14 w-full rounded-field" />
                ))}
              </div>
            ) : (
              <RolePermissionTable
                resourceId={
                  resourceFilter === 'all' ? undefined : resourceFilter
                }
                items={membership.items}
                initial={initial}
                selected={selected}
                staged={staged}
                disabled={!canWrite || pending}
                onToggle={(permissionId) =>
                  setSelected((current) =>
                    togglePermission(current, permissionId),
                  )
                }
              />
            )}
          </div>
        </section>

        {hasChanges && !builtIn ? (
          <section className="space-y-4">
            <div className="space-y-3 p-4">
              <div className="flex flex-wrap items-start justify-between gap-2">
                <div>
                  <p className="text-sm font-semibold">
                    {t('rolePermissionsReplaceTitle')}
                  </p>
                  <p className="mt-0.5 text-xs leading-5 text-muted">
                    {t('rolePermissionsReplaceDescription')}
                  </p>
                </div>
                <div className="flex flex-wrap gap-2">
                  <Chip size="sm" variant="soft" color="success">
                    <Chip.Label>
                      {t('rolePermissionsAddedCount', {
                        count: diff.added.length,
                      })}
                    </Chip.Label>
                  </Chip>
                  <Chip size="sm" variant="soft" color="warning">
                    <Chip.Label>
                      {t('rolePermissionsRemovedCount', {
                        count: diff.removed.length,
                      })}
                    </Chip.Label>
                  </Chip>
                  <Chip size="sm" variant="soft" color="default">
                    <Chip.Label>
                      {t('rolePermissionsSelectedCount', {
                        count: selected.size,
                      })}
                    </Chip.Label>
                  </Chip>
                </div>
              </div>

              {membership.status !== 'ready' || membership.hasNextPage ? (
                <Alert status="warning">
                  <Alert.Indicator />
                  <Alert.Content>
                    <Alert.Description>
                      {t('rolePermissionsIncompleteWarning')}
                    </Alert.Description>
                  </Alert.Content>
                </Alert>
              ) : null}
              {selectedDisabledItems.length > 0 ? (
                <p className="text-xs leading-5 text-muted">
                  {t('rolePermissionsDisabledSelectedHint', {
                    count: selectedDisabledItems.length,
                  })}
                </p>
              ) : null}

              <p className="text-xs leading-5 text-muted">
                {t('rolePermissionsAtomicHint')}
              </p>
              <div className="flex flex-wrap items-center gap-2">
                <Button
                  type="button"
                  isDisabled={!availability.allowed || !canWrite || pending}
                  onPress={confirmState.open}
                >
                  {pending ? (
                    <Spinner size="sm" aria-label={t('saving')} />
                  ) : (
                    <Save className="size-4" aria-hidden="true" />
                  )}
                  {t('rolePermissionsSaveAction')}
                </Button>
                <Button
                  type="button"
                  variant="secondary"
                  isDisabled={pending || !canWrite}
                  onPress={resetSelection}
                >
                  <Check className="size-4" aria-hidden="true" />
                  {t('rolePermissionsResetSelection')}
                </Button>
              </div>
              {!availability.allowed && membership.status === 'ready' ? (
                <p className="text-xs text-muted">
                  {submitAvailabilityMessage(availability.reason, t)}
                </p>
              ) : null}
            </div>
          </section>
        ) : null}
      </div>

      <ConfirmationDialog
        state={confirmState}
        title={t('rolePermissionsConfirmTitle')}
        description={t('rolePermissionsConfirmDescription')}
        confirmLabel={t('rolePermissionsConfirmAction')}
        pending={pending}
        destructive={diff.removed.length > 0}
        onConfirm={submit}
      >
        <dl className="grid gap-2 sm:grid-cols-2">
          <div>
            <dt className="text-xs text-muted">
              {t('rolePermissionsAddedLabel')}
            </dt>
            <dd>{t('rolePermissionsCount', { count: diff.added.length })}</dd>
          </div>
          <div>
            <dt className="text-xs text-muted">
              {t('rolePermissionsRemovedLabel')}
            </dt>
            <dd>{t('rolePermissionsCount', { count: diff.removed.length })}</dd>
          </div>
        </dl>
      </ConfirmationDialog>
    </ConsoleWorkspaceGate>
  )
}

type SubmitAvailabilityStatus = ReturnType<
  typeof rolePermissionSubmitAvailability
>['reason']

function submitAvailabilityMessage(
  status: SubmitAvailabilityStatus,
  t: ReturnType<typeof useTranslator>,
): string {
  const key: Record<SubmitAvailabilityStatus, MessageKey> = {
    ready: 'rolePermissionReady',
    'membership-loading': 'rolePermissionsIncompleteWarning',
    'membership-incomplete': 'rolePermissionsIncompleteWarning',
    'membership-error': 'roleMembershipLoadFailedDescription',
    'catalog-loading': 'rolePermissionsCatalogLoading',
    'catalog-error': 'rolePermissionsCatalogLoadFailed',
    'no-changes': 'rolePermissionsNoChanges',
  }
  return t(key[status])
}
