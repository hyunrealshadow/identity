import { useRoleDetailContext } from '../components/role-detail-context'
import { Alert, AlertDescription, AlertTitle } from '@identity/ui/components/alert'
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
import { Save, Power, PowerOff, TriangleAlert } from 'lucide-react'
import { useEffect, useMemo, useRef, useState } from 'react'

import { AsyncState } from '#/components/async-state'
import { ErrorDetails } from '#/components/error-details'
import { LocalizedTextField } from '#/components/localized-text-field'
import { RequestCorrelation } from '#/components/request-correlation'
import { StepUpPanel } from '#/components/step-up-panel'
import {
  type ConsoleRoleQuery,
  type UpdateRoleInput,
} from '#/generated/graphql'
import {
  failureDescriptionKey,
  failureTitleKey,
} from '#/lib/graphql/presentation'
import { formatDateTime } from '#/lib/format'
import { useLocale, useTranslator, type MessageKey } from '#/lib/i18n'
import { toast } from '#/lib/toast'
import {
  createLocalizedDraft,
  hasLocalizedDraftChanges,
  localizedMetadata,
  restoreLocalizedDraft,
  type LocalizedDraft,
  type LocalizedValues,
} from '#/lib/localized-values'
import { useWorkspace } from '#/lib/workspace'
import {
  RbacMutationFeedback,
  RbacNoticeAlert,
  type RbacNotice,
} from '#/components/rbac-feedback'
import { ConsoleWorkspaceGate } from '#/components/workspace-gate'
import { RoleStateDialog } from '../components/role-state-dialog'
import { RbacAccessRestricted } from '#/components/role-access'
import { useRoleMutations } from '#/modules/user-management/roles/hooks/role-mutations'
import {
  roleDisplayDescription,
  roleDisplayName,
  roleIsBuiltIn,
  withRoleDisplayFields,
} from '#/lib/localized-display'

import { clearDraft, readDraft, writeDraft } from '#/lib/draft-storage'
import {
  rbacFieldErrors,
  type RbacFeedbackState,
} from '#/lib/rbac-errors'
import { rbacScope } from '#/lib/rbac-scope'

type LocalField = 'metadata'

function draftFromRole(
  role: NonNullable<ConsoleRoleQuery['role']>,
): LocalizedDraft {
  return createLocalizedDraft(withRoleDisplayFields(role))
}

function draftKey(roleId: string): string {
  return `identity.console.role-settings.${roleId}`
}

function restoreSettings(
  role: NonNullable<ConsoleRoleQuery['role']>,
  roleId: string,
): LocalizedDraft {
  return restoreLocalizedDraft(
    readDraft<unknown>(draftKey(roleId)),
    withRoleDisplayFields(role),
  )
}

function roleMetadataChanged(
  role: NonNullable<ConsoleRoleQuery['role']>,
  draft: Pick<
    LocalizedDraft,
    'name' | 'description' | 'names' | 'descriptions'
  >,
): boolean {
  return hasLocalizedDraftChanges(withRoleDisplayFields(role), draft)
}

export function RoleDetailPage() {
  const t = useTranslator()
  const { locale, timeZone } = useLocale()
  const navigate = useNavigate()
  const workspace = useWorkspace()
  const scope = useMemo(
    () => rbacScope(workspace.data?.effectivePermissions),
    [workspace.data?.effectivePermissions],
  )
  const roleQuery = useRoleDetailContext()
  const mutations = useRoleMutations()
  // The state dialog stays mounted outside its trigger button.
  const stateDialog = useOverlayState()
  const [draft, setDraft] = useState<LocalizedDraft | null>(null)
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

  const role = roleQuery.data?.role ?? null
  const roleVersion = role ? `${role.id}:${role.version}` : undefined

  useEffect(() => {
    if (!role || !roleVersion) return
    if (initialized.current === roleVersion) return
    initialized.current = roleVersion
    setDraft(restoreSettings(role, role.id))
    setFieldErrors({})
    setFeedback(null)
  }, [roleVersion, role])

  useEffect(() => {
    if (!editing || !role || !draft) return
    writeDraft(draftKey(role.id), draft)
  }, [draft, role, editing])

  if (!scope.rolesRead) {
    return (
      <ConsoleWorkspaceGate>
        <RbacAccessRestricted
          title="rolesNoReadTitle"
          description="rolesNoReadDescription"

          onBack={() => void navigate({ to: '/roles' })}
          backLabel="backToRoles"
        />
      </ConsoleWorkspaceGate>
    )
  }

  if (roleQuery.status === 'error') {
    return (
      <ConsoleWorkspaceGate>
        {roleQuery.stepUp ? (
          <StepUpPanel
            stepUp={roleQuery.stepUp}
            hideDetails
            description={t('rbacStepUpDescription')}
            note={t('rbacStepUpNote')}
          />
        ) : (
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
        )}
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

  if (roleQuery.status !== 'ready' || !role || !draft) {
    return (
      <ConsoleWorkspaceGate>
        <AsyncState kind="loading" title={t('loading')} />
      </ConsoleWorkspaceGate>
    )
  }

  const readyRole = role
  const readyDraft = draft
  const display = withRoleDisplayFields(readyRole)
  const builtIn = roleIsBuiltIn(display)
  const displayName = roleDisplayName(display, locale)
  const displayDescription = roleDisplayDescription(display, locale)
  const metadataChanged = roleMetadataChanged(readyRole, readyDraft)
  const versionReady = Boolean(readyRole.version)

  function clearError(field: LocalField) {
    setLocalErrors((current) => {
      if (!current[field]) return current
      const next = { ...current }
      delete next[field]
      return next
    })
    setFieldErrors((current) => {
      if (!current[field]) return current
      const next = { ...current }
      delete next[field]
      return next
    })
  }

  function change(field: 'names' | 'descriptions', value: LocalizedValues) {
    if (builtIn) return
    setDraft((current) => (current ? { ...current, [field]: value } : current))
    setFeedback(null)
    clearError('metadata')
    setFieldErrors((current) => {
      const targets = [field, 'metadata', 'names', 'descriptions']
      if (!targets.some((target) => current[target])) return current
      const next = { ...current }
      for (const target of targets) delete next[target]
      return next
    })
  }

  async function reloadRole(): Promise<boolean> {
    const outcome = await roleQuery.refresh()
    const next = outcome?.role ?? null
    if (next) {
      initialized.current = `${next.id}:${next.version}`
      setDraft(draftFromRole(next))
      setAccessEnded(false)
      return true
    }
    setAccessEnded(true)
    return false
  }

  async function submit() {
    if (submitting.current || builtIn) return
    const nextErrors: Partial<Record<LocalField, MessageKey>> = {}
    if (metadataChanged && !readyDraft.name.trim()) {
      nextErrors.metadata = 'rolesMetadataNameRequired'
    }
    setLocalErrors(nextErrors)
    if (Object.keys(nextErrors).length > 0) return
    if (!metadataChanged) return
    if (!versionReady) return

    const input: UpdateRoleInput = {
      id: readyRole.id,
      expectedVersion: readyRole.version,
    }
    if (metadataChanged) {
      const metadata = localizedMetadata(readyDraft)
      input.name = metadata.name
      input.description = metadata.description
      input.names = metadata.names
      input.descriptions = metadata.descriptions
    }

    submitting.current = true
    setPending(true)
    setFeedback(null)
    setFieldErrors({})
    try {
      const result = await mutations.update(input)
      const payload = result.data?.updateRole ?? null
      if (!payload) {
        setFieldErrors(rbacFieldErrors(result.errors))
        setFeedback({
          errors: result.errors,
          failure: result.failure ?? {
            kind: 'invalid_response',
            code: 'missing_update_role_payload',
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
      clearDraft(draftKey(readyRole.id))
      toast.success(t('roleSettingsSavedToast'), {
        description: t('roleSettingsCommitted'),
      })
      if (result.partial) toast.warning(t('rbacPartialMutationNote'))
      const ok = await reloadRole()
      if (ok) {
        setNotice({
          kind: 'success',
          title: t('roleSettingsSavedTitle'),
          description: t('roleSettingsCommitted'),
        })
      } else {
        setNotice({
          kind: 'warning',
          title: t('roleRefreshFailedTitle'),
          description: t('roleRefreshFailedDescription'),
          requestId: result.requestId,
          traceId: result.traceId,
        })
      }
    } catch {
      setFeedback({
        errors: [],
        failure: { kind: 'network', code: 'role_update_request_failed' },
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
        {roleQuery.partial ? (
          <Alert variant="default" className="text-warning">
            <TriangleAlert aria-hidden="true" />
            <AlertTitle>{t('rolesPartialTitle')}</AlertTitle>
            <AlertDescription>
              {t('rolesPartialDescription')}
            </AlertDescription>
            <RequestCorrelation
              requestId={roleQuery.requestId}
              traceId={roleQuery.traceId}
            />
            <ErrorDetails issues={roleQuery.errors} />
          </Alert>
        ) : null}
        {!editing && !accessEnded && feedback ? (
          <RbacMutationFeedback
            feedback={feedback}
            onReload={() => void reloadRole()}
            reloadPending={roleQuery.refreshing}
          />
        ) : null}

        <div className="space-y-6">
          <div className="min-w-0">
            <section className="space-y-5 py-3">
              <div className="flex items-center justify-between gap-3">
                <h2 className="text-base font-semibold">
                  {t('roleSettingsTitle')}
                </h2>
                {!builtIn && scope.rolesWrite ? (
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
                  <dd className="text-sm">{displayName}</dd>
                </div>
                <div>
                  <dt className="mb-2 text-sm text-muted-foreground">
                    {t('rbacEntityDescription')}
                  </dt>
                  <dd className="whitespace-pre-wrap text-sm">
                    {displayDescription}
                  </dd>
                </div>
                <div>
                  <dt className="mb-2 text-sm text-muted-foreground">
                    {t('rbacEntityCreated')}
                  </dt>
                  <dd className="text-sm">
                    {formatDateTime(readyRole.createdAt, locale, timeZone)}
                  </dd>
                </div>
                <div>
                  <dt className="mb-2 text-sm text-muted-foreground">
                    {t('rbacEntityUpdated')}
                  </dt>
                  <dd className="text-sm">
                    {formatDateTime(readyRole.updatedAt, locale, timeZone)}
                  </dd>
                </div>
              </dl>
            </section>
            <Dialog
              open={editing}
              onOpenChange={(open) => {
                if (pending) return
                if (!open) {
                  setDraft(draftFromRole(readyRole))
                  clearDraft(draftKey(readyRole.id))
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
                      onReload={() => void reloadRole()}
                      reloadPending={roleQuery.refreshing}
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
                    onChange={(value) => change('names', value)}
                    isRequired
                    isDisabled={pending}
                    isReadOnly={builtIn || !scope.rolesWrite}
                    maxLength={256}
                    error={
                      localErrors.metadata
                        ? t(localErrors.metadata)
                        : (fieldErrors.name ??
                          fieldErrors.names ??
                          fieldErrors.metadata)
                    }
                  />
                  <LocalizedTextField
                    name="descriptions"
                    label={t('localizedDescription')}
                    defaultValue={readyDraft.description}
                    onDefaultValueChange={(value) => {
                      setDraft((current) =>
                        current ? { ...current, description: value } : current,
                      )
                      setFeedback(null)
                      setLocalErrors({})
                      setFieldErrors({})
                    }}
                    value={readyDraft.descriptions}
                    onChange={(value) => change('descriptions', value)}
                    multiline
                    isDisabled={pending}
                    isReadOnly={builtIn || !scope.rolesWrite}
                    maxLength={1024}
                    error={
                      fieldErrors.description ?? fieldErrors.descriptions
                    }
                  />
                </div>
                <DialogFooter>
                  <Button
                    type="button"
                    disabled={
                      !scope.rolesWrite ||
                      !versionReady ||
                      !metadataChanged
                    }
                    loading={pending}
                    onClick={() => void submit()}
                  >
                    {pending ? null : (
                      <Save className="size-4" aria-hidden="true" />
                    )}
                    {t('roleSettingsSaveAction')}
                  </Button>
                  <Button
                    type="button"
                    variant="outline"
                    disabled={pending || !scope.rolesWrite}
                    onClick={() => {
                      initialized.current = undefined
                      setDraft(draftFromRole(readyRole))
                      clearDraft(draftKey(readyRole.id))
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
              {!builtIn && scope.rolesWrite ? (
                <Button
                  variant={readyRole.enabled ? 'destructive' : 'secondary'}
                  onClick={stateDialog.open}
                  disabled={!readyRole.version}
                >
                  {readyRole.enabled ? (
                    <PowerOff className="size-4" aria-hidden="true" />
                  ) : (
                    <Power className="size-4" aria-hidden="true" />
                  )}
                  {t(readyRole.enabled ? 'rolesDisableAction' : 'rolesEnableAction')}
                </Button>
              ) : null}
              {!builtIn && scope.rolesWrite ? (
                <RoleStateDialog
                  state={stateDialog}
                  action={readyRole.enabled ? 'disable' : 'enable'}
                  role={readyRole}
                  onCommitted={() => void reloadRole()}
                />
              ) : null}
            </div>
          </div>
        </div>
      </div>
    </ConsoleWorkspaceGate>
  )
}
