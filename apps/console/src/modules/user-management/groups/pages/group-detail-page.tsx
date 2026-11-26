import { useGroupDetailContext } from '../components/group-detail-context'
import {
  Alert,
  AlertDescription,
  AlertTitle,
} from '@identity/ui/components/alert'
import { Button } from '@identity/ui/components/button'
import {
  Dialog,
  DialogContent,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@identity/ui/components/dialog'
import { useOverlayState } from '@identity/ui/hooks/use-overlay-state'
import { useNavigate } from '@tanstack/react-router'
import { Save, Trash2, Power, PowerOff, TriangleAlert } from 'lucide-react'
import { useEffect, useMemo, useRef, useState } from 'react'

import { toast } from '#/lib/toast'
import { AsyncState } from '#/components/async-state'
import { ErrorDetails } from '#/components/error-details'
import { LocalizedTextField } from '#/components/localized-text-field'
import { RequestCorrelation } from '#/components/request-correlation'
import { StepUpPanel } from '#/components/step-up-panel'
import {
  type ConsoleGroupQuery,
  type UpdateGroupInput,
} from '#/generated/graphql'
import {
  failureDescriptionKey,
  failureTitleKey,
} from '#/lib/graphql/presentation'
import { formatDateTime } from '#/lib/format'
import { useLocale, useTranslator, type MessageKey } from '#/lib/i18n'
import { useWorkspace } from '#/lib/workspace'
import {
  RbacMutationFeedback,
  RbacNoticeAlert,
  type RbacNotice,
} from '#/components/rbac-feedback'
import { ConsoleWorkspaceGate } from '#/components/workspace-gate'
import { useGroupMutations } from '#/modules/user-management/groups/hooks/group-mutations'
import {
  GroupDeleteDialog,
  GroupStateDialog,
} from '#/modules/user-management/groups/components/group-lifecycle-dialogs'
import {
  descriptionsChanged,
  groupEditDraftFromGroup,
  groupLocalizedMetadata,
  hasGroupName,
  namesChanged,
  restoreGroupTextDraft,
  type GroupSource,
  type GroupTextDraft,
} from '#/modules/user-management/groups/lib/groups-draft'
import { resolveLocalizedText } from '#/lib/localized-metadata'

import { clearDraft, readDraft, writeDraft } from '#/lib/draft-storage'
import {
  rbacFieldErrors,
  type RbacFeedbackState,
} from '#/lib/rbac-errors'
import { rbacScope } from '#/lib/rbac-scope'
import { RbacAccessRestricted } from '#/components/role-access'

type GroupNode = NonNullable<ConsoleGroupQuery['group']>

type LocalField = 'name'

function draftKey(groupId: string): string {
  return `identity.console.group-settings.${groupId}`
}

function restoreSettings(group: GroupNode, groupId: string): GroupTextDraft {
  const stored = readDraft<unknown>(draftKey(groupId))
  return restoreGroupTextDraft(stored, group)
}

export function GroupDetailPage() {
  const t = useTranslator()
  const { locale, timeZone } = useLocale()
  const navigate = useNavigate()
  const workspace = useWorkspace()
  const scope = useMemo(
    () => rbacScope(workspace.data?.effectivePermissions),
    [workspace.data?.effectivePermissions],
  )
  const groupQuery = useGroupDetailContext()
  const mutations = useGroupMutations()
  // Lifecycle dialogs stay mounted outside their trigger buttons.
  const stateDialog = useOverlayState()
  const deleteDialog = useOverlayState()
  const [draft, setDraft] = useState<GroupTextDraft | null>(null)
  const [localErrors, setLocalErrors] = useState<
    Partial<Record<LocalField, MessageKey>>
  >({})
  const [fieldErrors, setFieldErrors] = useState<Record<string, string>>({})
  const [feedback, setFeedback] = useState<RbacFeedbackState | null>(null)
  const [editing, setEditing] = useState(false)
  const [pending, setPending] = useState(false)
  const [notice, setNotice] = useState<RbacNotice | null>(null)
  const [accessEnded, setAccessEnded] = useState(false)
  const submitting = useRef(false)
  const initialized = useRef<string | undefined>(undefined)

  const group = groupQuery.data?.group ?? null
  const groupVersion = group ? `${group.id}:${group.version}` : undefined

  useEffect(() => {
    if (!group || !groupVersion) return
    if (initialized.current === groupVersion) return
    initialized.current = groupVersion
    setDraft(restoreSettings(group, group.id))
    setFieldErrors({})
    setFeedback(null)
  }, [groupVersion, group])

  useEffect(() => {
    if (!editing || !group || !draft) return
    writeDraft(draftKey(group.id), draft)
  }, [draft, group, editing])

  if (!scope.groupsRead) {
    return (
      <ConsoleWorkspaceGate>
        <RbacAccessRestricted
          title="groupsNoReadTitle"
          description="groupsNoReadDescription"

          onBack={() => void navigate({ to: '/groups' })}
          backLabel="backToGroups"
        />
      </ConsoleWorkspaceGate>
    )
  }

  if (groupQuery.status === 'error') {
    return (
      <ConsoleWorkspaceGate>
        {groupQuery.stepUp ? (
          <StepUpPanel
            stepUp={groupQuery.stepUp}
            hideDetails
            description={t('rbacStepUpDescription')}
            note={t('rbacStepUpNote')}
          />
        ) : (
          <AsyncState
            kind={groupQuery.forbidden ? 'forbidden' : 'error'}
            title={t(failureTitleKey(groupQuery.failure, groupQuery.forbidden))}
            description={t(
              failureDescriptionKey(groupQuery.failure, groupQuery.forbidden),
            )}
            requestId={groupQuery.requestId}
            traceId={groupQuery.traceId}
            issues={groupQuery.errors}
            onRetry={() => void groupQuery.refresh()}
          />
        )}
      </ConsoleWorkspaceGate>
    )
  }

  if (groupQuery.status === 'ready' && !group) {
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

  if (groupQuery.status !== 'ready' || !group || !draft) {
    return (
      <ConsoleWorkspaceGate>
        <AsyncState kind="loading" title={t('loading')} />
      </ConsoleWorkspaceGate>
    )
  }

  const readyGroup = group
  const readyDraft = draft
  const builtIn = readyGroup.builtIn
  const editable = !builtIn && scope.groupsWrite
  const versionReady = Boolean(readyGroup.version)
  const nameChanged = namesChanged(readyGroup as GroupSource, readyDraft)
  const descriptionChanged = descriptionsChanged(
    readyGroup as GroupSource,
    readyDraft,
  )
  const changed = nameChanged || descriptionChanged

  function clearError(field: LocalField) {
    setLocalErrors((current) => {
      if (!current[field]) return current
      const next = { ...current }
      delete next[field]
      return next
    })
    setFieldErrors((current) => {
      const targets = ['name', 'names'] as const
      if (!targets.some((target) => current[target])) return current
      const next = { ...current }
      for (const target of targets) delete next[target]
      return next
    })
  }

  function changeNames(names: GroupTextDraft['names']) {
    setDraft((current) => (current ? { ...current, names } : current))
    setFeedback(null)
    clearError('name')
  }

  function changeDescriptions(descriptions: GroupTextDraft['descriptions']) {
    setDraft((current) => (current ? { ...current, descriptions } : current))
    setFeedback(null)
  }

  async function reloadGroup(): Promise<boolean> {
    const outcome = await groupQuery.refresh()
    const next = outcome?.group ?? null
    if (next) {
      initialized.current = `${next.id}:${next.version}`
      setDraft(groupEditDraftFromGroup(next))
      setAccessEnded(false)
      return true
    }
    setAccessEnded(true)
    return false
  }

  async function submit() {
    if (submitting.current || builtIn || !scope.groupsWrite) return
    const nextErrors: Partial<Record<LocalField, MessageKey>> = {}
    if (!hasGroupName(readyDraft)) {
      nextErrors.name = 'groupsNameRequired'
    }
    setLocalErrors(nextErrors)
    if (Object.keys(nextErrors).length > 0) return
    if (!changed || !versionReady) return

    const input: UpdateGroupInput = {
      id: readyGroup.id,
      expectedVersion: readyGroup.version,
    }
    const metadata = groupLocalizedMetadata(readyDraft)
    if (nameChanged) {
      input.name = metadata.name
      input.names = metadata.names
    }
    if (descriptionChanged) {
      input.description = metadata.description
      input.descriptions = metadata.descriptions
    }

    submitting.current = true
    setPending(true)
    setFeedback(null)
    setFieldErrors({})
    try {
      const result = await mutations.update(input)
      const payload = result.data?.updateGroup ?? null
      if (!payload) {
        setFieldErrors(rbacFieldErrors(result.errors))
        setFeedback({
          errors: result.errors,
          failure: result.failure ?? {
            kind: 'invalid_response',
            code: 'missing_update_group_payload',
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
      setEditing(false)
      clearDraft(draftKey(readyGroup.id))
      toast.success(t('groupSettingsSavedToast'), {
        description: t('groupSettingsCommitted'),
      })
      if (result.partial) toast.warning(t('rbacPartialMutationNote'))
      const ok = await reloadGroup()
      if (ok) {
        setNotice({
          kind: 'success',
          title: t('groupSettingsSavedTitle'),
          description: t('groupSettingsCommitted'),
        })
      } else {
        setNotice({
          kind: 'warning',
          title: t('groupRefreshFailedTitle'),
          description: t('groupRefreshFailedDescription'),
          requestId: result.requestId,
          traceId: result.traceId,
        })
      }
    } catch {
      setFeedback({
        errors: [],
        failure: { kind: 'network', code: 'group_update_request_failed' },
        forbidden: false,
      })
    } finally {
      submitting.current = false
      setPending(false)
    }
  }

  return (
    <ConsoleWorkspaceGate>
      <div className="space-y-4">
        {notice ? (
          <RbacNoticeAlert notice={notice} onDismiss={() => setNotice(null)} />
        ) : null}
        {groupQuery.partial ? (
          <Alert variant="default" className="text-warning">
            <TriangleAlert aria-hidden="true" />
            <AlertTitle>{t('groupsPartialTitle')}</AlertTitle>
            <AlertDescription>{t('groupsPartialDescription')}</AlertDescription>
            <RequestCorrelation
              requestId={groupQuery.requestId}
              traceId={groupQuery.traceId}
            />
            <ErrorDetails issues={groupQuery.errors} />
          </Alert>
        ) : null}
        {!editing && !accessEnded && feedback ? (
          <RbacMutationFeedback
            feedback={feedback}
            onReload={() => void reloadGroup()}
            reloadPending={groupQuery.refreshing}
          />
        ) : null}

        <div className="space-y-6">
          <div className="min-w-0">
            <section className="space-y-5 py-3">
              <div className="flex items-center justify-between gap-3">
                <h2 className="text-base font-semibold">
                  {t('groupSettingsTitle')}
                </h2>
                {editable ? (
                  <Button
                    variant="outline"
                    size="sm"
                    onClick={() => setEditing(true)}
                  >
                    {t('rbacEntityEdit')}
                  </Button>
                ) : null}
              </div>
              <dl className="grid gap-x-8 gap-y-6 sm:grid-cols-2">
                <div>
                  <dt className="mb-2 text-sm text-muted-foreground">
                    {t('rbacEntityName')}
                  </dt>
                  <dd className="text-sm">
                    {resolveLocalizedText(readyGroup.names, locale) ??
                      readyGroup.name}
                  </dd>
                </div>
                <div>
                  <dt className="mb-2 text-sm text-muted-foreground">
                    {t('rbacEntityDescription')}
                  </dt>
                  <dd className="whitespace-pre-wrap text-sm">
                    {resolveLocalizedText(readyGroup.descriptions, locale) ??
                      readyGroup.description}
                  </dd>
                </div>
                <div>
                  <dt className="mb-2 text-sm text-muted-foreground">
                    {t('rbacEntityCreated')}
                  </dt>
                  <dd className="text-sm">
                    {formatDateTime(readyGroup.createdAt, locale, timeZone)}
                  </dd>
                </div>
                <div>
                  <dt className="mb-2 text-sm text-muted-foreground">
                    {t('rbacEntityUpdated')}
                  </dt>
                  <dd className="text-sm">
                    {formatDateTime(readyGroup.updatedAt, locale, timeZone)}
                  </dd>
                </div>
              </dl>
            </section>
            <Dialog
              open={editing}
              onOpenChange={(open) => {
                if (pending) return
                if (!open) {
                  setDraft(groupEditDraftFromGroup(readyGroup))
                  clearDraft(draftKey(readyGroup.id))
                  setLocalErrors({})
                  setFieldErrors({})
                  setFeedback(null)
                }
                setEditing(open)
              }}
            >
              <DialogContent
                showCloseButton={!pending}
                closeLabel={t('close')}
                className="sm:max-w-3xl"
              >
                <DialogHeader>
                  <DialogTitle>{t('rbacEntityEdit')}</DialogTitle>
                </DialogHeader>
                <div className="space-y-5">
                  {feedback ? (
                    <RbacMutationFeedback
                      feedback={feedback}
                      onReload={() => void reloadGroup()}
                      reloadPending={groupQuery.refreshing}
                    />
                  ) : null}
                  <LocalizedTextField
                    name="names"
                    label={t('localizedName')}
                    defaultValue={readyDraft.name}
                    onDefaultValueChange={(value) => {
                      setDraft((current) =>
                        current ? { ...current, name: value } : current,
                      )
                      setFeedback(null)
                      setLocalErrors({})
                      setFieldErrors({})
                    }}
                    value={readyDraft.names}
                    onChange={changeNames}
                    isReadOnly={!editable}
                    isDisabled={pending}
                    isRequired
                    maxLength={256}
                    error={
                      localErrors.name
                        ? t(localErrors.name)
                        : fieldErrors.names
                    }
                  />
                  <LocalizedTextField
                    name="descriptions"
                    label={t('localizedDescription')}
                    defaultValue={readyDraft.description}
                    onDefaultValueChange={(value) => {
                      setDraft((current) =>
                        current
                          ? { ...current, description: value }
                          : current,
                      )
                      setFeedback(null)
                      setLocalErrors({})
                      setFieldErrors({})
                    }}
                    value={readyDraft.descriptions}
                    onChange={changeDescriptions}
                    isReadOnly={!editable}
                    isDisabled={pending}
                    multiline
                    maxLength={1024}
                    error={
                      fieldErrors.description ?? fieldErrors.descriptions
                    }
                  />
                </div>
                <DialogFooter>
                  <Button
                    type="button"
                    disabled={!versionReady || !changed}
                    loading={pending}
                    onClick={() => void submit()}
                  >
                    {pending ? null : (
                      <Save className="size-4" aria-hidden="true" />
                    )}
                    {t('groupSettingsSaveAction')}
                  </Button>
                  <Button
                    type="button"
                    variant="outline"
                    disabled={pending}
                    onClick={() => {
                      initialized.current = undefined
                      setDraft(groupEditDraftFromGroup(readyGroup))
                      clearDraft(draftKey(readyGroup.id))
                      setLocalErrors({})
                      setFieldErrors({})
                      setFeedback(null)
                      setEditing(false)
                    }}
                  >
                    {t('cancel')}
                  </Button>
                </DialogFooter>
              </DialogContent>
            </Dialog>
          </div>

          <div className="space-y-4">
            <div className="flex flex-wrap gap-2">
              {!builtIn && scope.groupsWrite ? (
                <Button
                  variant={readyGroup.enabled ? 'destructive' : 'secondary'}
                  onClick={stateDialog.open}
                  disabled={!readyGroup.version}
                >
                  {readyGroup.enabled ? (
                    <PowerOff className="size-4" aria-hidden="true" />
                  ) : (
                    <Power className="size-4" aria-hidden="true" />
                  )}
                  {t(readyGroup.enabled ? 'groupsDisableAction' : 'groupsEnableAction')}
                </Button>
              ) : null}
              {!builtIn && scope.groupsWrite ? (
                <GroupStateDialog
                  state={stateDialog}
                  action={readyGroup.enabled ? 'disable' : 'enable'}
                  group={readyGroup}
                  onCommitted={() => void reloadGroup()}
                  onReload={() => void reloadGroup()}
                />
              ) : null}
              {!builtIn && scope.groupsDelete ? (
                <Button
                  variant="destructive"
                  onClick={deleteDialog.open}
                  disabled={!readyGroup.version}
                >
                  <Trash2 className="size-4" aria-hidden="true" />
                  {t('groupsDeleteAction')}
                </Button>
              ) : null}
              {!builtIn && scope.groupsDelete ? (
                <GroupDeleteDialog
                  state={deleteDialog}
                  group={readyGroup}
                  onCommitted={() => {
                    clearDraft(draftKey(readyGroup.id))
                    toast.success(t('groupsDeletedToast'))
                    void navigate({ to: '/groups' })
                  }}
                  onReload={() => void reloadGroup()}
                />
              ) : null}
            </div>
          </div>
        </div>
      </div>
    </ConsoleWorkspaceGate>
  )
}
