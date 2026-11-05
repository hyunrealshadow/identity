import {
  Alert,
  Button,
  Chip,
  Modal,
  Spinner,
  toast,
  useOverlayState,
} from '@heroui/react'
import { useNavigate } from '@tanstack/react-router'
import { ArrowLeft, Power, PowerOff, Save } from 'lucide-react'
import { useEffect, useMemo, useRef, useState } from 'react'

import { AsyncState } from '#/components/async-state'
import { useBreadcrumbLabel } from '#/components/app-breadcrumbs'
import { CopyButton } from '#/components/copy-button'
import { ErrorDetails } from '#/components/error-details'
import { LocalizedTextField } from '#/components/localized-text-field'
import { PageHeader } from '#/components/page-header'
import { RequestCorrelation } from '#/components/request-correlation'
import { StepUpPanel } from '#/components/step-up-panel'
import {
  type ConsolePermissionQuery,
  type ScopeStateInput,
  type UpdateScopeInput,
} from '#/generated/graphql'
import {
  failureDescriptionKey,
  failureTitleKey,
} from '#/lib/graphql/presentation'
import { formatDateTime } from '#/lib/format'
import { useLocale, useTranslator, type MessageKey } from '#/lib/i18n'
import { localizedMetadata, type LocalizedValues } from '#/lib/localized-values'
import { useWorkspace } from '#/lib/workspace'
import {
  RbacMutationFeedback,
  RbacNoticeAlert,
  type RbacNotice,
} from '#/modules/user-management/components/rbac-feedback'
import { ConsoleWorkspaceGate } from '#/modules/user-management/components/workspace-gate'
import { clearDraft, readDraft, writeDraft } from '#/lib/draft-storage'
import { rbacScope } from '#/modules/user-management/lib/rbac-scope'
import {
  clearPendingPermissionStateConfirmation,
  readPendingPermissionStateConfirmation,
  writePendingPermissionStateConfirmation,
} from '#/modules/client-management/resources/permissions/lib/permissions-state-confirmation'
import {
  permissionFieldErrors,
  type RbacFeedbackState,
} from '#/modules/client-management/resources/permissions/lib/permissions-errors'
import { usePermissionMutations } from '#/modules/client-management/resources/permissions/hooks/permission-mutations'
import { usePermissionDetail } from '#/modules/client-management/resources/permissions/hooks/use-permissions'
import { PermissionRoleReferences } from '#/modules/client-management/resources/permissions/components/permission-role-references'
import {
  hasPermissionMetadataChanges,
  permissionUpdateDraftFromSource,
  restorePermissionUpdateDraft,
  type PermissionUpdateDraft,
} from '#/modules/client-management/resources/permissions/lib/permissions-draft'
import { RbacAccessRestricted } from '#/modules/user-management/roles/components/role-access'
import { PermissionBuiltInChip } from '#/modules/user-management/roles/components/role-status'
import {
  permissionDisplayDescription,
  permissionDisplayName,
  permissionIsBuiltIn,
  withPermissionDisplayFields,
} from '#/modules/user-management/roles/lib/role-localization'

type LocalField = 'metadata'

function draftKey(permissionId: string): string {
  return `identity.console.permission-settings.${permissionId}`
}

function draftFromPermission(
  permission: NonNullable<ConsolePermissionQuery['permission']>,
): PermissionUpdateDraft {
  return permissionUpdateDraftFromSource(permission)
}

function PermissionStatusChip({ enabled }: { enabled: boolean }) {
  const t = useTranslator()
  return (
    <Chip size="sm" variant="soft" color={enabled ? 'success' : 'default'}>
      <Chip.Label>
        {t(enabled ? 'permissionsEnabled' : 'permissionsDisabled')}
      </Chip.Label>
    </Chip>
  )
}

export function PermissionDetailPage({
  resourceId,
  permissionId,
}: {
  resourceId: string
  permissionId: string
}) {
  const t = useTranslator()
  const { locale, timeZone } = useLocale()
  const navigate = useNavigate()
  const workspace = useWorkspace()
  const scope = useMemo(
    () => rbacScope(workspace.data?.effectivePermissions),
    [workspace.data?.effectivePermissions],
  )
  const permissionQuery = usePermissionDetail(
    permissionId,
    scope.permissionRead,
    scope.resourcesRead,
  )
  const mutations = usePermissionMutations()
  const [draft, setDraft] = useState<PermissionUpdateDraft | null>(null)
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

  const permission =
    permissionQuery.data?.permission?.resourceId === resourceId
      ? permissionQuery.data.permission
      : null
  const permissionVersion = permission
    ? `${permission.id}:${permission.version}`
    : undefined
  useBreadcrumbLabel(
    `/resources/${resourceId}/permissions/${permissionId}`,
    permission?.code,
  )

  useEffect(() => {
    if (!permission || !permissionVersion) return
    if (initialized.current === permissionVersion) return
    initialized.current = permissionVersion
    setDraft(
      restorePermissionUpdateDraft(
        readDraft<Partial<PermissionUpdateDraft>>(draftKey(permission.id)),
        permission,
      ),
    )
    setFieldErrors({})
    setFeedback(null)
  }, [permission, permissionVersion])

  useEffect(() => {
    if (!editing || !permission || !draft) return
    writeDraft(draftKey(permission.id), draft)
  }, [draft, permission, editing])

  const header = (
    <PageHeader
      title={
        permission
          ? permissionDisplayName(
              withPermissionDisplayFields(permission),
              locale,
            )
          : t('permissionsDetailTitle')
      }
      description={t('permissionsDetailDescription')}
      actions={
        <Button
          variant="secondary"
          isDisabled={pending}
          onPress={() =>
            void navigate({
              to: '/resources/$resourceId/permissions',
              params: { resourceId },
            })
          }
        >
          <ArrowLeft className="size-4" aria-hidden="true" />
          {t('backToPermissions')}
        </Button>
      }
    />
  )

  if (!scope.permissionRead) {
    return (
      <>
        {header}
        <ConsoleWorkspaceGate>
          <RbacAccessRestricted
            title="permissionsNoReadTitle"
            description="permissionsNoReadWriteOnlyDescription"

            onBack={() =>
              void navigate({
                to: '/resources/$resourceId/permissions',
                params: { resourceId },
              })
            }
            backLabel="backToPermissions"
          />
        </ConsoleWorkspaceGate>
      </>
    )
  }

  if (permissionQuery.status === 'error') {
    return (
      <>
        {header}
        <ConsoleWorkspaceGate>
          {permissionQuery.stepUp ? (
            <StepUpPanel
              stepUp={permissionQuery.stepUp}
              hideDetails
              description={t('rbacStepUpDescription')}
              note={t('permissionsStepUpNote')}
            />
          ) : (
            <AsyncState
              kind={permissionQuery.forbidden ? 'forbidden' : 'error'}
              title={t(
                failureTitleKey(
                  permissionQuery.failure,
                  permissionQuery.forbidden,
                ),
              )}
              description={t(
                failureDescriptionKey(
                  permissionQuery.failure,
                  permissionQuery.forbidden,
                ),
              )}
              requestId={permissionQuery.requestId}
              traceId={permissionQuery.traceId}
              issues={permissionQuery.errors}
              onRetry={() => void permissionQuery.refresh()}
            />
          )}
        </ConsoleWorkspaceGate>
      </>
    )
  }

  if (permissionQuery.status === 'ready' && !permission) {
    return (
      <>
        {header}
        <ConsoleWorkspaceGate>
          <AsyncState
            kind="notFound"
            title={t('notFoundTitle')}
            description={t('notFoundDescription')}
          />
        </ConsoleWorkspaceGate>
      </>
    )
  }

  if (permissionQuery.status !== 'ready' || !permission || !draft) {
    return (
      <>
        {header}
        <ConsoleWorkspaceGate>
          <AsyncState kind="loading" title={t('loading')} />
        </ConsoleWorkspaceGate>
      </>
    )
  }

  const readyPermission = permission
  const readyDraft = draft
  const display = withPermissionDisplayFields(readyPermission)
  const builtIn = permissionIsBuiltIn(display)
  const displayDescription = permissionDisplayDescription(display, locale)
  const metadataChanged = hasPermissionMetadataChanges(
    readyPermission,
    readyDraft,
  )
  const versionReady = Boolean(readyPermission.version)
  const canWrite = !builtIn && scope.permissionWrite
  const resourceLabel =
    readyPermission.resource?.name ||
    readyPermission.resource?.uri ||
    t('permissionsResourceUnavailable')

  function clearError(field: LocalField) {
    setLocalErrors((current) => {
      if (!current[field]) return current
      const next = { ...current }
      delete next[field]
      return next
    })
    setFieldErrors((current) => {
      const targets = [field, 'metadata', 'names', 'descriptions']
      if (!targets.some((target) => current[target])) return current
      const next = { ...current }
      for (const target of targets) delete next[target]
      return next
    })
  }

  function changeMetadata(
    field: 'names' | 'descriptions',
    value: LocalizedValues,
  ) {
    if (builtIn) return
    setDraft((current) => (current ? { ...current, [field]: value } : current))
    setFeedback(null)
    clearError('metadata')
  }

  async function reloadPermission(): Promise<boolean> {
    const outcome = await permissionQuery.refresh()
    const next = outcome?.permission ?? null
    if (next) {
      initialized.current = `${next.id}:${next.version}`
      setDraft(draftFromPermission(next))
      setAccessEnded(false)
      return true
    }
    setAccessEnded(true)
    return false
  }

  async function submit() {
    if (submitting.current || builtIn || !canWrite) return
    const nextErrors: Partial<Record<LocalField, MessageKey>> = {}
    if (metadataChanged && !readyDraft.name.trim()) {
      nextErrors.metadata = 'permissionsMetadataNameRequired'
    }
    setLocalErrors(nextErrors)
    if (Object.keys(nextErrors).length > 0) return
    if (!metadataChanged) return
    if (!versionReady) return

    const metadata = localizedMetadata(readyDraft)
    const input: UpdateScopeInput = {
      id: readyPermission.id,
      expectedVersion: readyPermission.version,
      name: metadata.name,
      description: metadata.description,
      names: metadata.names,
      descriptions: metadata.descriptions,
    }

    submitting.current = true
    setPending(true)
    setFeedback(null)
    setFieldErrors({})
    try {
      const result = await mutations.update(input)
      const payload = result.data?.updatePermission ?? null
      if (!payload) {
        setFieldErrors(permissionFieldErrors(result.errors))
        setFeedback({
          errors: result.errors,
          failure: result.failure ?? {
            kind: 'invalid_response',
            code: 'missing_update_permission_payload',
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
      clearDraft(draftKey(readyPermission.id))
      toast.success(t('permissionSettingsSavedToast'), {
        description: t('permissionSettingsCommitted'),
      })
      if (result.partial) toast.warning(t('rbacPartialMutationNote'))
      const ok = await reloadPermission()
      if (ok) {
        setNotice({
          kind: 'success',
          title: t('permissionSettingsSavedTitle'),
          description: t('permissionSettingsCommitted'),
        })
      } else {
        setNotice({
          kind: 'warning',
          title: t('permissionRefreshFailedTitle'),
          description: t('permissionRefreshFailedDescription'),
          requestId: result.requestId,
          traceId: result.traceId,
        })
      }
    } catch {
      setFeedback({
        errors: [],
        failure: {
          kind: 'network',
          code: 'permission_update_request_failed',
        },
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
        {header}
        {notice ? (
          <RbacNoticeAlert notice={notice} onDismiss={() => setNotice(null)} />
        ) : null}
        {permissionQuery.partial ? (
          <Alert status="warning">
            <Alert.Indicator />
            <Alert.Content>
              <Alert.Title>{t('permissionsPartialTitle')}</Alert.Title>
              <Alert.Description>
                {t('permissionsPartialDescription')}
              </Alert.Description>
              <RequestCorrelation
                requestId={permissionQuery.requestId}
                traceId={permissionQuery.traceId}
              />
              <ErrorDetails issues={permissionQuery.errors} />
            </Alert.Content>
          </Alert>
        ) : null}
        {!editing && !accessEnded && feedback ? (
          <RbacMutationFeedback
            feedback={feedback}
            onReload={() => void reloadPermission()}
            reloadPending={permissionQuery.refreshing}
            conflictTitleKey="permissionsConflictTitle"
            conflictDescriptionKey="permissionsConflictDescription"
          />
        ) : null}

        <div className="space-y-6">
          <div className="min-w-0">
            <section className="space-y-5 py-3">
              <div className="flex items-center justify-between gap-3">
                <div className="flex flex-wrap items-center gap-2">
                  <h2 className="text-base font-semibold">
                    {t('permissionSettingsTitle')}
                  </h2>
                  <PermissionBuiltInChip builtIn={builtIn} />
                  <PermissionStatusChip enabled={readyPermission.enabled} />
                </div>
                {canWrite ? (
                  <Button
                    size="sm"
                    variant="secondary"
                    onPress={() => setEditing(true)}
                  >
                    {t('rbacEntityEdit')}
                  </Button>
                ) : null}
              </div>
              <dl className="grid gap-x-8 gap-y-6 sm:grid-cols-2">
                <div>
                  <dt className="mb-2 text-sm text-muted">
                    {t('permissionsColumnPermission')}
                  </dt>
                  <dd className="flex items-center gap-1">
                    <code className="break-all text-sm">
                      {readyPermission.code}
                    </code>
                    <CopyButton
                      value={readyPermission.code}
                      label={t('permissionCodeLabel')}
                    />
                  </dd>
                </div>
                <div>
                  <dt className="mb-2 text-sm text-muted">
                    {t('rbacApiResource')}
                  </dt>
                  <dd className="text-sm">{resourceLabel}</dd>
                </div>
                <div className="sm:col-span-2">
                  <dt className="mb-2 text-sm text-muted">
                    {t('rbacEntityDescription')}
                  </dt>
                  <dd className="whitespace-pre-wrap text-sm">
                    {displayDescription}
                  </dd>
                </div>
                <div>
                  <dt className="mb-2 text-sm text-muted">
                    {t('rbacEntityCreated')}
                  </dt>
                  <dd className="text-sm">
                    {formatDateTime(
                      readyPermission.createdAt,
                      locale,
                      timeZone,
                    )}
                  </dd>
                </div>
                <div>
                  <dt className="mb-2 text-sm text-muted">
                    {t('rbacEntityUpdated')}
                  </dt>
                  <dd className="text-sm">
                    {formatDateTime(
                      readyPermission.updatedAt,
                      locale,
                      timeZone,
                    )}
                  </dd>
                </div>
              </dl>
            </section>
            <Modal
              isOpen={editing}
              onOpenChange={(open) => {
                if (pending) return
                if (!open) {
                  setDraft(draftFromPermission(readyPermission))
                  clearDraft(draftKey(readyPermission.id))
                  setLocalErrors({})
                  setFieldErrors({})
                  setFeedback(null)
                }
                setEditing(open)
              }}
            >
              <Modal.Backdrop isDismissable={!pending}>
                <Modal.Container size="lg">
                  <Modal.Dialog className="sm:max-w-3xl">
                    <Modal.CloseTrigger
                      isDisabled={pending}
                      aria-label={t('close')}
                    />
                    <Modal.Header>
                      <Modal.Heading>{t('rbacEntityEdit')}</Modal.Heading>
                    </Modal.Header>
                    <Modal.Body>
                      <div className="space-y-5">
                        {feedback ? (
                          <RbacMutationFeedback
                            feedback={feedback}
                            onReload={() => void reloadPermission()}
                            reloadPending={permissionQuery.refreshing}
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
                          onChange={(value) => changeMetadata('names', value)}
                          isRequired
                          isDisabled={pending}
                          isReadOnly={builtIn || !canWrite}
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
                              current
                                ? { ...current, description: value }
                                : current,
                            )
                            setFeedback(null)
                            setLocalErrors({})
                            setFieldErrors({})
                          }}
                          value={readyDraft.descriptions}
                          onChange={(value) =>
                            changeMetadata('descriptions', value)
                          }
                          multiline
                          isDisabled={pending}
                          isReadOnly={builtIn || !canWrite}
                          maxLength={1024}
                          error={
                            fieldErrors.description ?? fieldErrors.descriptions
                          }
                        />
                      </div>
                    </Modal.Body>
                    <Modal.Footer>
                      <Button
                        type="button"
                        isDisabled={
                          pending || !versionReady || !metadataChanged
                        }
                        onPress={() => void submit()}
                      >
                        {pending ? (
                          <Spinner size="sm" aria-label={t('saving')} />
                        ) : (
                          <Save className="size-4" aria-hidden="true" />
                        )}
                        {t('permissionSettingsSaveAction')}
                      </Button>
                      <Button
                        type="button"
                        variant="secondary"
                        isDisabled={pending}
                        onPress={() => {
                          initialized.current = undefined
                          setDraft(draftFromPermission(readyPermission))
                          clearDraft(draftKey(readyPermission.id))
                          setLocalErrors({})
                          setFieldErrors({})
                          setFeedback(null)
                          setEditing(false)
                        }}
                      >
                        {t('cancel')}
                      </Button>
                    </Modal.Footer>
                  </Modal.Dialog>
                </Modal.Container>
              </Modal.Backdrop>
            </Modal>
          </div>

          <div className="space-y-4">
            <div className="flex flex-wrap gap-2">
              {canWrite ? (
                <PermissionStateDialog
                  action={readyPermission.enabled ? 'disable' : 'enable'}
                  permission={readyPermission}
                  onCommitted={() => void reloadPermission()}
                />
              ) : null}
            </div>
          </div>
        </div>
        <PermissionRoleReferences permissionId={readyPermission.id} />
      </div>
    </ConsoleWorkspaceGate>
  )
}

export function PermissionStateDialog({
  action,
  permission,
  onCommitted,
}: {
  action: 'enable' | 'disable'
  permission: NonNullable<ConsolePermissionQuery['permission']>
  onCommitted: () => void
}) {
  const t = useTranslator()
  const { locale } = useLocale()
  const state = useOverlayState()
  const mutations = usePermissionMutations()
  const displayName = permissionDisplayName(
    withPermissionDisplayFields(permission),
    locale,
  )
  const [feedback, setFeedback] = useState<RbacFeedbackState | null>(null)
  const [pending, setPending] = useState(false)
  const submitting = useRef(false)
  const [storedConfirmation] = useState(() =>
    readPendingPermissionStateConfirmation(permission.id),
  )
  // Keep the version the user actually confirmed. A later read must not
  // silently replace it or auto-submit the write after reauthentication.
  const expectedVersion = useRef(
    storedConfirmation && storedConfirmation.action === action
      ? storedConfirmation.expectedVersion
      : permission.version,
  )
  const restoreAttempted = useRef(false)
  const opened = useRef(false)
  const completed = useRef(false)

  useEffect(() => {
    if (restoreAttempted.current) return
    if (!storedConfirmation) {
      restoreAttempted.current = true
      return
    }
    if (
      storedConfirmation.permissionId !== permission.id ||
      storedConfirmation.action !== action
    ) {
      clearPendingPermissionStateConfirmation(permission.id)
      restoreAttempted.current = true
      return
    }
    if (!permission.version) return
    expectedVersion.current = storedConfirmation.expectedVersion
    restoreAttempted.current = true
    // Reopen the exact pending confirmation, but require a new explicit
    // confirm press before any mutation is sent.
    state.open()
  }, [action, permission.id, permission.version, state, storedConfirmation])

  useEffect(() => {
    if (state.isOpen) {
      opened.current = true
      return
    }
    if (opened.current) {
      if (!completed.current) {
        clearPendingPermissionStateConfirmation(permission.id)
      }
      opened.current = false
      completed.current = false
    }
    setFeedback(null)
    setPending(false)
  }, [permission.id, state.isOpen])

  function openConfirmation() {
    if (!permission.version) return
    expectedVersion.current = permission.version
    writePendingPermissionStateConfirmation({
      permissionId: permission.id,
      action,
      expectedVersion: permission.version,
    })
    state.open()
  }

  async function submit() {
    if (submitting.current) return
    if (permissionIsBuiltIn(withPermissionDisplayFields(permission))) return
    const version = expectedVersion.current || permission.version
    if (!version) return
    submitting.current = true
    setPending(true)
    setFeedback(null)
    const input: ScopeStateInput = {
      id: permission.id,
      expectedVersion: version,
    }
    try {
      const result =
        action === 'enable'
          ? await mutations.enable(input)
          : await mutations.disable(input)
      const data = result.data as {
        enablePermission?: { permissionId: string; version: string } | null
        disablePermission?: { permissionId: string; version: string } | null
      } | null
      const payload = data?.enablePermission ?? data?.disablePermission ?? null
      if (!payload) {
        setFeedback({
          errors: result.errors,
          failure: result.failure ?? {
            kind: 'invalid_response',
            code: 'missing_permission_state_payload',
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
      clearPendingPermissionStateConfirmation(permission.id)
      state.close()
      toast.success(
        t(
          action === 'enable'
            ? 'permissionsEnabledToast'
            : 'permissionsDisabledToast',
        ),
        { description: t('permissionSettingsCommitted') },
      )
      if (result.partial) toast.warning(t('rbacPartialMutationNote'))
      onCommitted()
    } catch {
      setFeedback({
        errors: [],
        failure: {
          kind: 'network',
          code: 'permission_state_request_failed',
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
      <Button
        variant={action === 'disable' ? 'danger-soft' : 'secondary'}
        onPress={openConfirmation}
        isDisabled={!permission.version}
      >
        {action === 'enable' ? (
          <Power className="size-4" aria-hidden="true" />
        ) : (
          <PowerOff className="size-4" aria-hidden="true" />
        )}
        {t(
          action === 'enable'
            ? 'permissionsEnableAction'
            : 'permissionsDisableAction',
        )}
      </Button>
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
                      {t(
                        action === 'enable'
                          ? 'permissionsEnableTitle'
                          : 'permissionsDisableTitle',
                      )}
                    </Modal.Heading>
                  </Modal.Header>
                  <Modal.Body>
                    <p className="text-sm leading-6 text-muted">
                      {t(
                        action === 'enable'
                          ? 'permissionsEnableDescription'
                          : 'permissionsDisableDescription',
                      )}
                    </p>
                    <p className="mt-3 text-sm font-medium">{displayName}</p>
                    {feedback ? (
                      <div className="mt-4">
                        <RbacMutationFeedback
                          feedback={feedback}
                          onReload={() => {
                            state.close()
                            onCommitted()
                          }}
                          conflictTitleKey="permissionsConflictTitle"
                          conflictDescriptionKey="permissionsConflictDescription"
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
                      variant={action === 'disable' ? 'danger' : 'primary'}
                      isDisabled={pending || !expectedVersion.current}
                      onPress={() => void submit()}
                    >
                      {pending ? (
                        <Spinner size="sm" aria-label={t('working')} />
                      ) : null}
                      {t(
                        action === 'enable'
                          ? 'permissionsEnableConfirm'
                          : 'permissionsDisableConfirm',
                      )}
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
