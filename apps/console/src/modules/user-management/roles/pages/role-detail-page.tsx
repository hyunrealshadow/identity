import { useRoleDetailContext } from '../components/role-detail-context'
import {
  Alert,
  Button,
  Modal,
  Spinner,
  toast,
  useOverlayState,
} from '@heroui/react'
import { useNavigate } from '@tanstack/react-router'
import { Save, Power, PowerOff } from 'lucide-react'
import { useEffect, useMemo, useRef, useState } from 'react'

import { AsyncState } from '#/components/async-state'
import { ErrorDetails } from '#/components/error-details'
import { LocalizedTextField } from '#/components/localized-text-field'
import { RequestCorrelation } from '#/components/request-correlation'
import { StepUpPanel } from '#/components/step-up-panel'
import {
  type ConsoleRoleQuery,
  type RoleStateInput,
  type UpdateRoleInput,
} from '#/generated/graphql'
import {
  failureDescriptionKey,
  failureTitleKey,
} from '#/lib/graphql/presentation'
import { formatDateTime } from '#/lib/format'
import { useLocale, useTranslator, type MessageKey } from '#/lib/i18n'
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
} from '#/modules/user-management/components/rbac-feedback'
import { ConsoleWorkspaceGate } from '#/modules/user-management/components/workspace-gate'
import { RbacAccessRestricted } from '#/modules/user-management/roles/components/role-access'
import { useRoleMutations } from '#/modules/user-management/roles/hooks/role-mutations'
import {
  roleDisplayDescription,
  roleDisplayName,
  roleIsBuiltIn,
  withRoleDisplayFields,
} from '#/modules/user-management/roles/lib/role-localization'

import { clearDraft, readDraft, writeDraft } from '#/lib/draft-storage'
import {
  rbacFieldErrors,
  type RbacFeedbackState,
} from '#/modules/user-management/lib/rbac-errors'
import { rbacScope } from '#/modules/user-management/lib/rbac-scope'

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
          <Alert status="warning">
            <Alert.Indicator />
            <Alert.Content>
              <Alert.Title>{t('rolesPartialTitle')}</Alert.Title>
              <Alert.Description>
                {t('rolesPartialDescription')}
              </Alert.Description>
              <RequestCorrelation
                requestId={roleQuery.requestId}
                traceId={roleQuery.traceId}
              />
              <ErrorDetails issues={roleQuery.errors} />
            </Alert.Content>
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
                    variant="secondary"
                    size="sm"
                    onPress={() => setEditing(true)}
                  >
                    {t('rbacEntityEdit')}
                  </Button>
                ) : null}
              </div>
              <dl className="grid gap-x-8 gap-y-6 sm:grid-cols-2">
                <div>
                  <dt className="mb-2 text-sm text-muted">
                    {t('rbacEntityName')}
                  </dt>
                  <dd className="text-sm">{displayName}</dd>
                </div>
                <div>
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
                    {formatDateTime(readyRole.createdAt, locale, timeZone)}
                  </dd>
                </div>
                <div>
                  <dt className="mb-2 text-sm text-muted">
                    {t('rbacEntityUpdated')}
                  </dt>
                  <dd className="text-sm">
                    {formatDateTime(readyRole.updatedAt, locale, timeZone)}
                  </dd>
                </div>
              </dl>
            </section>
            <Modal
              isOpen={editing}
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
                              current
                                ? { ...current, description: value }
                                : current,
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
                    </Modal.Body>
                    <Modal.Footer>
                      <Button
                        type="button"
                        isDisabled={
                          pending ||
                          !scope.rolesWrite ||
                          !versionReady ||
                          !metadataChanged
                        }
                        onPress={() => void submit()}
                      >
                        {pending ? (
                          <Spinner size="sm" aria-label={t('saving')} />
                        ) : (
                          <Save className="size-4" aria-hidden="true" />
                        )}
                        {t('roleSettingsSaveAction')}
                      </Button>
                      <Button
                        type="button"
                        variant="secondary"
                        isDisabled={pending || !scope.rolesWrite}
                        onPress={() => {
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
                    </Modal.Footer>
                  </Modal.Dialog>
                </Modal.Container>
              </Modal.Backdrop>
            </Modal>
          </div>

          <div className="space-y-4">
            <div className="flex flex-wrap gap-2">
              {!builtIn && scope.rolesWrite ? (
                <RoleStateDialog
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

function RoleStateDialog({
  action,
  role,
  onCommitted,
}: {
  action: 'enable' | 'disable'
  role: NonNullable<ConsoleRoleQuery['role']>
  onCommitted: () => void
}) {
  const t = useTranslator()
  const { locale } = useLocale()
  const state = useOverlayState()
  const mutations = useRoleMutations()
  const displayName = roleDisplayName(withRoleDisplayFields(role), locale)
  const [feedback, setFeedback] = useState<RbacFeedbackState | null>(null)
  const [pending, setPending] = useState(false)
  const submitting = useRef(false)

  useEffect(() => {
    if (state.isOpen) return
    setFeedback(null)
    setPending(false)
  }, [state.isOpen])

  async function submit() {
    if (submitting.current) return
    if (roleIsBuiltIn(withRoleDisplayFields(role))) return
    submitting.current = true
    setPending(true)
    setFeedback(null)
    const input: RoleStateInput = {
      id: role.id,
      expectedVersion: role.version,
    }
    try {
      const result =
        action === 'enable'
          ? await mutations.enable(input)
          : await mutations.disable(input)
      const data = result.data as {
        enableRole?: { roleId: string; version: string } | null
        disableRole?: { roleId: string; version: string } | null
      } | null
      const payload = data?.enableRole ?? data?.disableRole ?? null
      if (!payload) {
        setFeedback({
          errors: result.errors,
          failure: result.failure ?? {
            kind: 'invalid_response',
            code: 'missing_role_state_payload',
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
      toast.success(
        t(action === 'enable' ? 'rolesEnabledToast' : 'rolesDisabledToast'),
        { description: t('roleSettingsCommitted') },
      )
      if (result.partial) toast.warning(t('rbacPartialMutationNote'))
      onCommitted()
    } catch {
      setFeedback({
        errors: [],
        failure: { kind: 'network', code: 'role_state_request_failed' },
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
        onPress={state.open}
        isDisabled={!role.version}
      >
        {action === 'enable' ? (
          <Power className="size-4" aria-hidden="true" />
        ) : (
          <PowerOff className="size-4" aria-hidden="true" />
        )}
        {t(action === 'enable' ? 'rolesEnableAction' : 'rolesDisableAction')}
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
                          ? 'rolesEnableTitle'
                          : 'rolesDisableTitle',
                      )}
                    </Modal.Heading>
                  </Modal.Header>
                  <Modal.Body>
                    <p className="text-sm leading-6 text-muted">
                      {t(
                        action === 'enable'
                          ? 'rolesEnableDescription'
                          : 'rolesDisableDescription',
                      )}
                    </p>
                    <p className="mt-3 text-sm font-medium">{displayName}</p>
                    {feedback ? (
                      <div className="mt-4">
                        <RbacMutationFeedback feedback={feedback} />
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
                      isDisabled={pending || !role.version}
                      onPress={() => void submit()}
                    >
                      {pending ? (
                        <Spinner size="sm" aria-label={t('working')} />
                      ) : null}
                      {t(
                        action === 'enable'
                          ? 'rolesEnableConfirm'
                          : 'rolesDisableConfirm',
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
