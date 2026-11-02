import { Alert, Button, Spinner, toast } from '@heroui/react'
import { useNavigate } from '@tanstack/react-router'
import { ArrowLeft, Save } from 'lucide-react'
import { useEffect, useMemo, useRef, useState } from 'react'

import { AsyncState } from '#/components/async-state'
import { useBreadcrumbLabel } from '#/components/app-breadcrumbs'
import { ErrorDetails } from '#/components/error-details'
import { PageHeader } from '#/components/page-header'
import { RequestCorrelation } from '#/components/request-correlation'
import { StepUpPanel } from '#/components/step-up-panel'
import {
  UserEditRestricted,
  UserReadRestricted,
} from '#/modules/user-management/users/components/user-access'
import {
  fieldErrorsFromIssues,
  type MutationFeedbackState,
} from '#/modules/user-management/users/lib/user-errors'
import { MutationFeedback } from '#/modules/user-management/users/components/user-feedback'
import {
  UserProfileFields,
  UserTextField,
} from '#/modules/user-management/users/components/user-form-fields'
import {
  editDraftFromUser,
  editDraftSnapshot,
  editDraftSnapshotHasContent,
  emailChangeResetsVerification,
  restoreEditDraft,
  updateDraftChanged,
  updateInputFromDraft,
  type ProjectedUser,
  type UserEditDraft,
  type UserProfileField,
} from '#/modules/user-management/users/lib/user-form'
import { clearDraft, readDraft, writeDraft } from '#/lib/draft-storage'
import { useUserMutations } from '#/modules/user-management/users/hooks/user-mutations'
import { userManagementScope } from '#/modules/user-management/users/lib/user-scope'
import { useUserDetail } from '#/modules/user-management/users/hooks/use-user-detail'
import { BEFORE_AUTH_REDIRECT_EVENT } from '#/lib/auth/events'
import {
  failureDescriptionKey,
  failureTitleKey,
} from '#/lib/graphql/presentation'
import { useTranslator, type MessageKey } from '#/lib/i18n'
import { useWorkspace } from '#/lib/workspace'

function editDraftKey(userId: string): string {
  return `identity.console.user.edit.${userId}`
}

type LocalField = 'username' | 'email' | 'version' | 'noChanges'

const EDIT_PROFILE_FIELDS: ReadonlyArray<UserProfileField> = [
  'givenName',
  'familyName',
  'nickname',
]

export function UserEditPage({ userId }: { userId: string }) {
  const t = useTranslator()
  const navigate = useNavigate()
  const workspace = useWorkspace()
  const permissions = workspace.data?.effectivePermissions ?? null
  const scope = useMemo(() => userManagementScope(permissions), [permissions])
  const detail = useUserDetail(userId, Boolean(scope.read && scope.update))
  useBreadcrumbLabel(`/users/${userId}`, detail.user?.username)
  const mutations = useUserMutations()
  const submitting = useRef(false)
  const initialized = useRef<string | undefined>(undefined)
  const draftKey = editDraftKey(userId)
  const draftRef = useRef<UserEditDraft | null>(null)
  const userRef = useRef<ProjectedUser | null>(null)
  const persistDraft = useRef(true)

  const [draft, setDraft] = useState<UserEditDraft | null>(null)
  const [localErrors, setLocalErrors] = useState<
    Partial<Record<LocalField, MessageKey>>
  >({})
  const [fieldErrors, setFieldErrors] = useState<Record<string, string>>({})
  const [feedback, setFeedback] = useState<MutationFeedbackState | null>(null)
  const [pending, setPending] = useState(false)

  const versionKey = detail.user
    ? `${detail.user.id}:${detail.user.version ?? ''}`
    : undefined

  useEffect(() => {
    draftRef.current = draft
  }, [draft])

  useEffect(() => {
    userRef.current = detail.user ?? null
  }, [detail.user])

  useEffect(() => {
    if (!detail.user || !versionKey || detail.user.id !== userId) return
    if (initialized.current === versionKey) return
    initialized.current = versionKey
    persistDraft.current = true
    const currentUser = detail.user
    userRef.current = currentUser
    const restored = restoreEditDraft(currentUser, readDraft<unknown>(draftKey))
    const next = restored ?? editDraftFromUser(currentUser)
    draftRef.current = next
    setDraft(next)
    setLocalErrors({})
    setFieldErrors({})
    setFeedback(null)
  }, [detail.user, draftKey, userId, versionKey])

  // Keep the scoped draft current while editing. The latest saved snapshot is
  // also written synchronously by the auth-redirect listener below.
  useEffect(() => {
    if (!persistDraft.current) return
    const currentUser = userRef.current
    const currentDraft = draftRef.current
    if (!currentUser || !currentDraft || currentUser.id !== userId) return
    const snapshot = editDraftSnapshot(currentUser, currentDraft)
    if (editDraftSnapshotHasContent(snapshot)) {
      writeDraft(draftKey, snapshot)
    } else {
      clearDraft(draftKey)
    }
  }, [draft, detail.user, draftKey, userId])

  useEffect(() => {
    if (typeof window === 'undefined') return
    function persistBeforeRedirect() {
      if (!persistDraft.current) return
      const currentUser = userRef.current
      const currentDraft = draftRef.current
      if (!currentUser || !currentDraft || currentUser.id !== userId) return
      const snapshot = editDraftSnapshot(currentUser, currentDraft)
      if (editDraftSnapshotHasContent(snapshot)) {
        writeDraft(draftKey, snapshot)
      } else {
        clearDraft(draftKey)
      }
    }
    window.addEventListener(BEFORE_AUTH_REDIRECT_EVENT, persistBeforeRedirect)
    return () =>
      window.removeEventListener(
        BEFORE_AUTH_REDIRECT_EVENT,
        persistBeforeRedirect,
      )
  }, [draftKey, userId])

  const header = (
    <PageHeader
      title={t('usersEditTitle')}
      description={detail.user?.username}
      actions={
        <Button
          variant="secondary"
          isDisabled={pending}
          onPress={() => {
            leaveEditor()
            void navigate({
              to: '/users/$userId',
              params: { userId: detail.user?.id ?? userId },
            })
          }}
        >
          <ArrowLeft className="size-4" aria-hidden="true" />
          {t('usersBackToDetail')}
        </Button>
      }
    />
  )

  if (workspace.status === 'idle' || workspace.status === 'loading') {
    return (
      <>
        {header}
        <AsyncState kind="loading" title={t('loading')} />
      </>
    )
  }

  if (workspace.status === 'error' && !permissions) {
    return (
      <>
        {header}
        {workspace.stepUp ? (
          <StepUpPanel
            stepUp={workspace.stepUp}
            hideDetails
            description={t('usersStepUpDescription')}
            note={t('usersStepUpNote')}
          />
        ) : (
          <AsyncState
            kind={workspace.forbidden ? 'forbidden' : 'error'}
            title={t(failureTitleKey(workspace.failure, workspace.forbidden))}
            description={t(
              failureDescriptionKey(workspace.failure, workspace.forbidden),
            )}
            requestId={workspace.requestId}
            traceId={workspace.traceId}
            issues={workspace.errors}
            onRetry={() => void workspace.refresh()}
          />
        )}
      </>
    )
  }

  if (!permissions) {
    return (
      <>
        {header}
        <AsyncState
          kind={workspace.forbidden ? 'forbidden' : 'partial'}
          title={t(
            workspace.forbidden
              ? failureTitleKey(workspace.failure, true)
              : 'partialTitle',
          )}
          description={t(
            workspace.forbidden
              ? failureDescriptionKey(workspace.failure, true)
              : 'partialDescription',
          )}
          requestId={workspace.requestId}
          traceId={workspace.traceId}
          issues={workspace.errors}
          onRetry={() => void workspace.refresh()}
        />
      </>
    )
  }

  if (!scope.read) {
    return (
      <>
        {header}
        <UserReadRestricted
          scope={scope}
          onCreate={() => void navigate({ to: '/users/new' })}
          onGoHome={() => void navigate({ to: '/' })}
        />
      </>
    )
  }

  if (!scope.update) {
    return (
      <>
        {header}
        <UserEditRestricted
          scope={scope}
          onBack={() =>
            void navigate({
              to: '/users/$userId',
              params: { userId },
            })
          }
        />
      </>
    )
  }

  if (detail.notFound) {
    return (
      <>
        {header}
        <AsyncState
          kind="notFound"
          title={t('notFoundTitle')}
          description={t('notFoundDescription')}
          action={
            <Button
              variant="secondary"
              onPress={() => void navigate({ to: '/users' })}
            >
              {t('backToUsers')}
            </Button>
          }
        />
      </>
    )
  }

  if (detail.status === 'error') {
    return (
      <>
        {header}
        {detail.stepUp ? (
          <StepUpPanel
            stepUp={detail.stepUp}
            hideDetails
            description={t('usersStepUpDescription')}
            note={t('usersStepUpNote')}
          />
        ) : (
          <AsyncState
            kind={detail.forbidden ? 'forbidden' : 'error'}
            title={t(failureTitleKey(detail.failure, detail.forbidden))}
            description={t(
              failureDescriptionKey(detail.failure, detail.forbidden),
            )}
            requestId={detail.requestId}
            traceId={detail.traceId}
            issues={detail.errors}
            onRetry={() => void detail.refresh()}
          />
        )}
      </>
    )
  }

  const user = detail.user
  if (detail.status !== 'ready' || !user || !draft) {
    return (
      <>
        {header}
        <AsyncState kind="loading" title={t('loading')} />
      </>
    )
  }

  // Read-only aliases keep the narrowed values available inside the handlers
  // below; function-declaration closures do not retain the guard's narrowing.
  const readyUser: ProjectedUser = user
  const readyDraft: UserEditDraft = draft

  const dirty = updateDraftChanged(readyUser, readyDraft)
  const emailChanged = emailChangeResetsVerification(readyUser, readyDraft)
  const versionReady = Boolean(readyUser.version)

  function clearLocalError(field: LocalField) {
    setLocalErrors((current) => {
      if (!current[field]) return current
      const next = { ...current }
      delete next[field]
      return next
    })
  }

  function clearFieldError(...fields: string[]) {
    setFieldErrors((current) => {
      if (!fields.some((field) => current[field])) return current
      const next = { ...current }
      for (const field of fields) delete next[field]
      return next
    })
  }

  function changeDraft(update: (current: UserEditDraft) => UserEditDraft) {
    const current = draftRef.current
    if (!current) return
    const next = update(current)
    draftRef.current = next
    setDraft(next)
  }

  function setAccountField(field: 'username' | 'email', value: string) {
    changeDraft((current) => ({ ...current, [field]: value }))
    setFeedback(null)
    clearLocalError(field)
    clearLocalError('noChanges')
    clearFieldError(field)
  }

  function setProfileField(field: UserProfileField, value: string) {
    changeDraft((current) => ({
      ...current,
      profile: { ...current.profile, [field]: value },
    }))
    setFeedback(null)
    clearLocalError('noChanges')
    clearFieldError(field)
  }

  function leaveEditor() {
    persistDraft.current = false
    clearDraft(draftKey)
  }

  async function reloadConflict(): Promise<boolean> {
    const outcome = await detail.reload()
    if (outcome.kind === 'ready' && outcome.user) {
      const reloadedUser: ProjectedUser = outcome.user
      initialized.current = `${reloadedUser.id}:${reloadedUser.version ?? ''}`
      const next = editDraftFromUser(reloadedUser)
      userRef.current = reloadedUser
      draftRef.current = next
      setDraft(next)
      setLocalErrors({})
      setFieldErrors({})
      setFeedback(null)
      return true
    }
    return false
  }

  async function submit() {
    if (submitting.current) return

    const nextLocal: Partial<Record<LocalField, MessageKey>> = {}
    if (!readyDraft.username.trim())
      nextLocal.username = 'usersUsernameRequired'
    if (!readyDraft.email.trim()) nextLocal.email = 'usersEmailRequired'
    if (!readyUser.version) {
      nextLocal.version = 'usersStateVersionUnavailable'
    }
    if (!dirty) nextLocal.noChanges = 'usersEditNoChanges'

    if (Object.keys(nextLocal).length > 0) {
      setLocalErrors(nextLocal)
      return
    }

    const input = updateInputFromDraft(readyUser, readyDraft)
    if (!input) {
      setLocalErrors({ version: 'usersStateVersionUnavailable' })
      return
    }

    submitting.current = true
    setPending(true)
    setFeedback(null)
    setFieldErrors({})
    setLocalErrors({})

    try {
      const result = await mutations.update(input)
      const payload = result.data?.updateUser ?? null
      if (!payload) {
        setFieldErrors(fieldErrorsFromIssues(result.errors))
        setFeedback({
          errors: result.errors,
          failure: result.failure ?? {
            kind: 'invalid_response',
            code: 'missing_update_user_payload',
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

      leaveEditor()
      toast.success(t('usersEditSuccessToast'), {
        description: t('usersEditCommitted'),
      })
      if (result.partial) {
        toast.warning(t('usersPartialMutationNote'))
      }
      void navigate({
        to: '/users/$userId',
        params: { userId: payload.userId },
        replace: true,
      })
    } catch {
      setFeedback({
        errors: [],
        failure: { kind: 'network', code: 'user_update_request_failed' },
        forbidden: false,
      })
    } finally {
      submitting.current = false
      setPending(false)
    }
  }

  const usernameError =
    fieldErrors.username ??
    (localErrors.username ? t(localErrors.username) : undefined)
  const emailError =
    fieldErrors.email ?? (localErrors.email ? t(localErrors.email) : undefined)
  const versionError = localErrors.version ? t(localErrors.version) : undefined
  const noChangesError = localErrors.noChanges
    ? t(localErrors.noChanges)
    : undefined

  return (
    <>
      {header}

      <div className="max-w-3xl space-y-6">
        {detail.partial ? (
          <Alert status="warning">
            <Alert.Indicator />
            <Alert.Content>
              <Alert.Title>{t('usersPartialTitle')}</Alert.Title>
              <Alert.Description>
                {t('usersPartialDescription')}
              </Alert.Description>
              <RequestCorrelation
                requestId={detail.requestId}
                traceId={detail.traceId}
              />
              <ErrorDetails issues={detail.errors} />
            </Alert.Content>
          </Alert>
        ) : null}

        {feedback ? (
          <MutationFeedback
            feedback={feedback}
            onReload={() => void reloadConflict()}
            reloadPending={detail.refreshing}
          />
        ) : null}

        <form
          noValidate
          aria-busy={pending}
          onSubmit={(event) => {
            event.preventDefault()
            void submit()
          }}
        >
          <div className="space-y-8">
            <section className="space-y-4">
              <div>
                <h2 className="text-base font-semibold tracking-tight">
                  {t('usersSectionAccount')}
                </h2>
              </div>

              {!versionReady || versionError ? (
                <Alert status="warning">
                  <Alert.Indicator />
                  <Alert.Content>
                    <Alert.Title>
                      {versionError ?? t('usersStateVersionUnavailable')}
                    </Alert.Title>
                  </Alert.Content>
                </Alert>
              ) : null}

              <div className="grid gap-4 sm:grid-cols-2">
                <UserTextField
                  name="username"
                  label={t('usersFieldUsername')}
                  value={readyDraft.username}
                  onChange={(value) => setAccountField('username', value)}
                  autoComplete="off"
                  isRequired
                  isDisabled={pending}
                  error={usernameError}
                />
                <UserTextField
                  name="email"
                  label={t('usersFieldEmail')}
                  value={readyDraft.email}
                  onChange={(value) => setAccountField('email', value)}
                  type="email"
                  autoComplete="email"
                  inputMode="email"
                  isRequired
                  isDisabled={pending}
                  description={
                    emailChanged ? t('usersEditEmailVerifiedReset') : undefined
                  }
                  error={emailError}
                />
              </div>
            </section>

            <section className="space-y-4 border-t border-separator pt-6">
              <div>
                <h2 className="text-base font-semibold tracking-tight">
                  {t('usersSectionProfile')}
                </h2>
              </div>
              <UserProfileFields
                draft={readyDraft.profile}
                onChange={setProfileField}
                errors={fieldErrors}
                isDisabled={pending}
                fields={EDIT_PROFILE_FIELDS}
              />
            </section>

            {noChangesError ? (
              <p className="text-xs leading-5 text-muted">{noChangesError}</p>
            ) : null}

            <div className="flex flex-wrap items-center gap-2 border-t border-separator pt-5">
              <Button
                type="submit"
                isDisabled={pending || !dirty || !versionReady}
              >
                {pending ? (
                  <Spinner size="sm" aria-label={t('usersEditPending')} />
                ) : (
                  <Save className="size-4" aria-hidden="true" />
                )}
                {t('usersEditSaveAction')}
              </Button>
              <Button
                type="button"
                variant="secondary"
                isDisabled={pending}
                onPress={() => {
                  leaveEditor()
                  void navigate({
                    to: '/users/$userId',
                    params: { userId: readyUser.id },
                  })
                }}
              >
                {t('cancel')}
              </Button>
            </div>
          </div>
        </form>
      </div>
    </>
  )
}
