import {
  Alert,
  AlertDescription,
  AlertTitle,
} from '@identity/ui/components/alert'
import { Button } from '@identity/ui/components/button'
import { Card, CardContent } from '@identity/ui/components/card'
import { Spinner } from '@identity/ui/components/spinner'
import { useNavigate } from '@tanstack/react-router'
import { ArrowLeft, ChevronDown, Plus, TriangleAlert } from 'lucide-react'
import { useEffect, useMemo, useRef, useState } from 'react'

import { AsyncState } from '#/components/async-state'
import { PageHeader } from '#/components/page-header'
import { StepUpPanel } from '#/components/step-up-panel'
import { UserCreateRestricted } from '#/modules/user-management/users/components/user-access'
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
  createDraftFromEmpty,
  createDraftSnapshot,
  createDraftSnapshotHasContent,
  createInputFromDraft,
  restoreCreateDraft,
  USER_PROFILE_FIELDS,
  type CreateUserDraft,
  type UserProfileField,
} from '#/modules/user-management/users/lib/user-form'
import { clearDraft, readDraft, writeDraft } from '#/lib/draft-storage'
import { toast } from '#/lib/toast'
import { useUserMutations } from '#/modules/user-management/users/hooks/user-mutations'
import { userManagementScope } from '#/modules/user-management/users/lib/user-scope'
import { BEFORE_AUTH_REDIRECT_EVENT } from '#/lib/auth/events'
import {
  failureDescriptionKey,
  failureTitleKey,
} from '#/lib/graphql/presentation'
import { useTranslator, type MessageKey } from '#/lib/i18n'
import { useWorkspace } from '#/lib/workspace'

type LocalField = 'username' | 'email' | 'password'

const CREATE_DRAFT_KEY = 'identity.console.user.create'
const BASIC_PROFILE_FIELDS = ['givenName', 'familyName', 'nickname'] as const
const ADDITIONAL_PROFILE_FIELDS = USER_PROFILE_FIELDS.filter(
  (field) => !BASIC_PROFILE_FIELDS.some((basic) => basic === field),
)

export function UserCreatePage() {
  const t = useTranslator()
  const navigate = useNavigate()
  const workspace = useWorkspace()
  const permissions = workspace.data?.effectivePermissions ?? null
  const scope = useMemo(() => userManagementScope(permissions), [permissions])
  const mutations = useUserMutations()
  const submitting = useRef(false)
  const persistDraft = useRef(true)

  const [initialDraft] = useState(() => {
    const restored = restoreCreateDraft(readDraft<unknown>(CREATE_DRAFT_KEY))
    return {
      draft: restored ?? createDraftFromEmpty(),
      restored:
        restored !== null &&
        createDraftSnapshotHasContent(createDraftSnapshot(restored)),
    }
  })
  const [draft, setDraft] = useState<CreateUserDraft>(initialDraft.draft)
  const draftRef = useRef<CreateUserDraft>(initialDraft.draft)
  const [showAdditionalProfile, setShowAdditionalProfile] = useState(() =>
    ADDITIONAL_PROFILE_FIELDS.some(
      (field) => initialDraft.draft.profile[field] !== '',
    ),
  )
  const [restoredPasswordHint, setRestoredPasswordHint] = useState(
    initialDraft.restored,
  )
  const [localErrors, setLocalErrors] = useState<
    Partial<Record<LocalField, MessageKey>>
  >({})
  const [fieldErrors, setFieldErrors] = useState<Record<string, string>>({})
  const [feedback, setFeedback] = useState<MutationFeedbackState | null>(null)
  const [pending, setPending] = useState(false)
  const [created, setCreated] = useState<{
    userId: string
    version: string
  } | null>(null)

  useEffect(() => {
    draftRef.current = draft
  }, [draft])

  // Persist only non-sensitive create values; the password is never included.
  useEffect(() => {
    if (!persistDraft.current) return
    const snapshot = createDraftSnapshot(draftRef.current)
    if (createDraftSnapshotHasContent(snapshot)) {
      writeDraft(CREATE_DRAFT_KEY, snapshot)
    } else {
      clearDraft(CREATE_DRAFT_KEY)
    }
  }, [draft])

  useEffect(() => {
    if (typeof window === 'undefined') return
    function persistBeforeRedirect() {
      const snapshot = createDraftSnapshot(draftRef.current)
      if (createDraftSnapshotHasContent(snapshot)) {
        writeDraft(CREATE_DRAFT_KEY, snapshot)
      } else {
        clearDraft(CREATE_DRAFT_KEY)
      }
    }
    window.addEventListener(BEFORE_AUTH_REDIRECT_EVENT, persistBeforeRedirect)
    return () =>
      window.removeEventListener(
        BEFORE_AUTH_REDIRECT_EVENT,
        persistBeforeRedirect,
      )
  }, [])

  const header = (
    <PageHeader
      title={t('usersNewTitle')}
      description={t('usersNewDescription')}
      actions={
        <Button
          variant="secondary"
          disabled={pending}
          onClick={() => {
            leaveCreate()
            void navigate({ to: '/users' })
          }}
        >
          <ArrowLeft className="size-4" aria-hidden="true" />
          {t('backToUsers')}
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

  if (!scope.create) {
    return (
      <>
        {header}
        <UserCreateRestricted
          scope={scope}
          onGoHome={() => void navigate({ to: '/' })}
        />
      </>
    )
  }

  if (created) {
    return (
      <>
        {header}
        <Card className="console-card border border-border">
          <CardContent className="p-6 sm:p-8">
            <span className="flex size-10 items-center justify-center rounded-lg bg-muted text-muted-foreground">
              <Plus className="size-5" aria-hidden="true" />
            </span>
            <h2 className="mt-4 text-lg font-semibold tracking-tight">
              {t('usersCreateCannotReadTitle')}
            </h2>
            <p className="mt-2 max-w-2xl text-sm leading-6 text-muted-foreground">
              {t('usersCreateCannotReadDescription', {
                userId: created.userId,
              })}
            </p>
            <dl className="mt-4 grid gap-3 text-sm sm:grid-cols-2">
              <div>
                <dt className="text-xs font-medium text-muted-foreground">
                  {t('usersUserIdLabel')}
                </dt>
                <dd className="mt-0.5 break-all font-mono text-xs">
                  {created.userId}
                </dd>
              </div>
              <div>
                <dt className="text-xs font-medium text-muted-foreground">
                  {t('usersVersionLabel')}
                </dt>
                <dd className="mt-0.5 font-mono text-xs">{created.version}</dd>
              </div>
            </dl>
            <div className="mt-5 flex flex-wrap gap-2">
              <Button
                onClick={() => {
                  setCreated(null)
                  resetCreate()
                }}
              >
                <Plus className="size-4" aria-hidden="true" />
                {t('usersCreateAnother')}
              </Button>
              <Button
                variant="secondary"
                onClick={() => void navigate({ to: '/' })}
              >
                {t('goHome')}
              </Button>
            </div>
          </CardContent>
        </Card>
      </>
    )
  }

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

  function changeDraft(update: (current: CreateUserDraft) => CreateUserDraft) {
    const next = update(draftRef.current)
    draftRef.current = next
    setDraft(next)
  }

  function setAccountField(
    field: 'username' | 'email' | 'password',
    value: string,
  ) {
    changeDraft((current) => ({ ...current, [field]: value }))
    if (field === 'password' && value !== '') {
      setRestoredPasswordHint(false)
    }
    setFeedback(null)
    clearLocalError(field)
    clearFieldError(field)
  }

  function setProfileField(field: UserProfileField, value: string) {
    changeDraft((current) => ({
      ...current,
      profile: { ...current.profile, [field]: value },
    }))
    setFeedback(null)
    clearFieldError(field)
  }

  function leaveCreate() {
    persistDraft.current = false
    clearDraft(CREATE_DRAFT_KEY)
  }

  function resetCreate() {
    clearDraft(CREATE_DRAFT_KEY)
    const next = createDraftFromEmpty()
    draftRef.current = next
    setDraft(next)
    persistDraft.current = true
    setRestoredPasswordHint(false)
    setLocalErrors({})
    setFieldErrors({})
    setFeedback(null)
  }

  function validate(): boolean {
    const next: Partial<Record<LocalField, MessageKey>> = {}
    if (!draft.username.trim()) next.username = 'usersUsernameRequired'
    if (!draft.email.trim()) next.email = 'usersEmailRequired'
    if (!draft.password) next.password = 'usersCreatePasswordRequired'
    setLocalErrors(next)
    return Object.keys(next).length === 0
  }

  async function submit() {
    if (submitting.current || !validate()) return

    submitting.current = true
    setPending(true)
    setFeedback(null)
    setFieldErrors({})
    try {
      const result = await mutations.create(createInputFromDraft(draft))
      const payload = result.data?.createUser ?? null
      if (!payload) {
        setFieldErrors(fieldErrorsFromIssues(result.errors))
        setFeedback({
          errors: result.errors,
          failure: result.failure ?? {
            kind: 'invalid_response',
            code: 'missing_create_user_payload',
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

      // Clear the sensitive local password immediately after a committed write.
      leaveCreate()
      changeDraft((current) => ({ ...current, password: '' }))
      toast.success(t('usersCreateSuccessToast'), {
        description: t('usersCreateCommitted'),
      })
      if (result.partial) {
        toast.warning(t('usersPartialMutationNote'))
      }

      if (scope.read) {
        void navigate({
          to: '/users/$userId',
          params: { userId: payload.userId },
          replace: true,
        })
      } else {
        setCreated({
          userId: payload.userId,
          version: payload.version,
        })
      }
    } catch {
      setFeedback({
        errors: [],
        failure: { kind: 'network', code: 'user_create_request_failed' },
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
  const passwordError =
    fieldErrors.password ??
    (localErrors.password ? t(localErrors.password) : undefined)

  return (
    <>
      {header}

      {!scope.read ? (
        <Alert variant="default" className="mb-4 text-warning">
          <TriangleAlert aria-hidden="true" />
          <AlertTitle>{t('usersCreateOnlyAccessTitle')}</AlertTitle>
          <AlertDescription>{t('usersCreateReadWarning')}</AlertDescription>
        </Alert>
      ) : null}

      {feedback ? (
        <div className="mb-4">
          <MutationFeedback feedback={feedback} />
        </div>
      ) : null}

      <form
        noValidate
        aria-busy={pending}
        onSubmit={(event) => {
          event.preventDefault()
          void submit()
        }}
      >
        <div className="max-w-3xl space-y-8">
          <section className="space-y-4">
            <h2 className="text-base font-semibold tracking-tight">
              {t('usersSectionAccount')}
            </h2>
            <div className="grid gap-4 sm:grid-cols-2">
              <UserTextField
                name="username"
                label={t('usersFieldUsername')}
                value={draft.username}
                onChange={(value) => setAccountField('username', value)}
                autoComplete="off"
                isRequired
                isDisabled={pending}
                error={usernameError}
              />
              <UserTextField
                name="email"
                label={t('usersFieldEmail')}
                value={draft.email}
                onChange={(value) => setAccountField('email', value)}
                type="email"
                autoComplete="email"
                inputMode="email"
                isRequired
                isDisabled={pending}
                error={emailError}
              />
              <UserTextField
                name="password"
                label={t('usersFieldPassword')}
                value={draft.password}
                onChange={(value) => setAccountField('password', value)}
                type="password"
                autoComplete="new-password"
                isRequired
                isDisabled={pending}
                description={
                  restoredPasswordHint
                    ? t('usersCreateDraftPasswordHint')
                    : t('usersFieldPasswordDescription')
                }
                error={passwordError}
              />
            </div>
          </section>

          <section className="space-y-4 border-t border-border pt-6">
            <h2 className="text-base font-semibold tracking-tight">
              {t('usersSectionProfile')}
            </h2>
            <UserProfileFields
              draft={draft.profile}
              onChange={setProfileField}
              errors={fieldErrors}
              isDisabled={pending}
              fields={BASIC_PROFILE_FIELDS}
            />
            <details
              className="group"
              open={
                showAdditionalProfile ||
                ADDITIONAL_PROFILE_FIELDS.some((field) =>
                  Boolean(fieldErrors[field]),
                )
              }
              onToggle={(event) =>
                setShowAdditionalProfile(event.currentTarget.open)
              }
            >
              <summary className="console-focus flex w-fit cursor-pointer list-none items-center gap-2 py-2 text-sm text-muted-foreground hover:text-foreground [&::-webkit-details-marker]:hidden">
                {t('usersAdditionalProfile')}
                <ChevronDown
                  className="size-4 transition-transform group-open:rotate-180"
                  aria-hidden="true"
                />
              </summary>
              <div className="pt-3">
                <UserProfileFields
                  draft={draft.profile}
                  onChange={setProfileField}
                  errors={fieldErrors}
                  isDisabled={pending}
                  fields={ADDITIONAL_PROFILE_FIELDS}
                />
              </div>
            </details>
          </section>

          <div className="flex flex-wrap items-center gap-2 border-t border-border pt-6">
            <Button type="submit" disabled={pending}>
              {pending ? (
                <Spinner aria-label={t('usersCreatePending')} />
              ) : (
                <Plus className="size-4" aria-hidden="true" />
              )}
              {t('usersCreateAction')}
            </Button>
            <Button
              type="button"
              variant="secondary"
              disabled={pending}
              onClick={() => {
                leaveCreate()
                void navigate({ to: '/users' })
              }}
            >
              {t('cancel')}
            </Button>
          </div>
        </div>
      </form>
    </>
  )
}
