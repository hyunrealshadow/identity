import { Alert, Button, Card, Spinner, toast } from '@heroui/react'
import { useNavigate } from '@tanstack/react-router'
import { ArrowLeft, Plus } from 'lucide-react'
import { useEffect, useMemo, useRef, useState } from 'react'

import { LocalizedTextField } from '#/components/localized-text-field'
import { PageHeader } from '#/components/page-header'

import type { CreateRoleInput } from '#/gql/graphql'
import { useTranslator, type MessageKey } from '#/lib/i18n'
import {
  createLocalizedDraft,
  localizedMetadata,
  restoreLocalizedDraft,
  type LocalizedDraft,
  type LocalizedValues,
} from '#/lib/localized-values'
import { useWorkspace } from '#/lib/workspace'
import { RbacMutationFeedback } from '#/modules/user-management/components/rbac-feedback'
import { ConsoleWorkspaceGate } from '#/modules/user-management/components/workspace-gate'
import { RbacAccessRestricted } from '#/modules/user-management/roles/components/role-access'
import { useRoleMutations } from '#/modules/user-management/roles/hooks/role-mutations'
import { clearDraft, readDraft, writeDraft } from '#/lib/draft-storage'
import {
  rbacFieldErrors,
  type RbacFeedbackState,
} from '#/modules/user-management/lib/rbac-errors'
import { rbacScope } from '#/modules/user-management/lib/rbac-scope'

const DRAFT_KEY = 'identity.console.role-create.draft'

function restoreDraft(): LocalizedDraft {
  return restoreLocalizedDraft(readDraft<unknown>(DRAFT_KEY))
}

type LocalField = 'metadata'

export function RoleCreatePage() {
  const t = useTranslator()
  const navigate = useNavigate()
  const workspace = useWorkspace()
  const scope = useMemo(
    () => rbacScope(workspace.data?.effectivePermissions),
    [workspace.data?.effectivePermissions],
  )
  const mutations = useRoleMutations()
  const submitting = useRef(false)
  const [draft, setDraft] = useState<LocalizedDraft>(restoreDraft)
  const [localErrors, setLocalErrors] = useState<
    Partial<Record<LocalField, MessageKey>>
  >({})
  const [fieldErrors, setFieldErrors] = useState<Record<string, string>>({})
  const [feedback, setFeedback] = useState<RbacFeedbackState | null>(null)
  const [pending, setPending] = useState(false)
  const [created, setCreated] = useState<{
    roleId: string
    version: string
  } | null>(null)

  useEffect(() => {
    writeDraft(DRAFT_KEY, draft)
  }, [draft])

  const header = (
    <PageHeader
      title={t('rolesNewTitle')}
      description={t('rolesNewDescription')}
      actions={
        <Button
          variant="secondary"
          isDisabled={pending}
          onPress={() => void navigate({ to: '/roles' })}
        >
          <ArrowLeft className="size-4" aria-hidden="true" />
          {t('backToRoles')}
        </Button>
      }
    />
  )

  if (created) {
    return (
      <>
        {header}
        <ConsoleWorkspaceGate>
          <Card className="console-card border border-border">
            <Card.Content className="p-6 sm:p-8">
              <span className="flex size-10 items-center justify-center rounded-lg bg-surface-secondary text-muted">
                <Plus className="size-5" aria-hidden="true" />
              </span>
              <h2 className="mt-4 text-lg font-semibold tracking-tight">
                {t('rolesCreateWriteOnlyTitle')}
              </h2>
              <p className="mt-2 max-w-2xl text-sm leading-6 text-muted">
                {t('rolesCreateWriteOnlyDescription', {
                  roleId: created.roleId,
                })}
              </p>
              <dl className="mt-4 grid gap-3 text-sm sm:grid-cols-2">
                <div>
                  <dt className="text-xs font-medium text-muted">
                    {t('rolesIdLabel')}
                  </dt>
                  <dd className="mt-0.5 break-all font-mono text-xs">
                    {created.roleId}
                  </dd>
                </div>
                <div>
                  <dt className="text-xs font-medium text-muted">
                    {t('rolesVersionLabel')}
                  </dt>
                  <dd className="mt-0.5 font-mono text-xs">
                    {created.version}
                  </dd>
                </div>
              </dl>
              <div className="mt-5 flex flex-wrap gap-2">
                <Button
                  onPress={() => {
                    setCreated(null)
                    setDraft(createLocalizedDraft())
                    clearDraft(DRAFT_KEY)
                  }}
                >
                  <Plus className="size-4" aria-hidden="true" />
                  {t('rolesCreateAnother')}
                </Button>
                <Button
                  variant="secondary"
                  onPress={() => void navigate({ to: '/roles' })}
                >
                  {t('backToRoles')}
                </Button>
              </div>
            </Card.Content>
          </Card>
        </ConsoleWorkspaceGate>
      </>
    )
  }

  if (!scope.rolesWrite) {
    return (
      <>
        {header}
        <ConsoleWorkspaceGate>
          <RbacAccessRestricted
            title="rolesCreateNoPermissionTitle"
            description="rolesCreateNoPermissionDescription"

            onBack={() => void navigate({ to: '/roles' })}
            backLabel="backToRoles"
          />
        </ConsoleWorkspaceGate>
      </>
    )
  }

  function validate(current: LocalizedDraft): boolean {
    const next: Partial<Record<LocalField, MessageKey>> = {}
    if (!current.name.trim()) {
      next.metadata = 'rolesMetadataNameRequired'
    }
    setLocalErrors(next)
    return Object.keys(next).length === 0
  }

  async function submit() {
    if (submitting.current || !scope.rolesWrite) return
    if (!validate(draft)) return
    submitting.current = true
    setPending(true)
    setFeedback(null)
    setFieldErrors({})
    try {
      const input: CreateRoleInput = localizedMetadata(draft)
      const result = await mutations.create(input)
      const payload = result.data?.createRole ?? null
      if (!payload) {
        setFieldErrors(rbacFieldErrors(result.errors))
        setFeedback({
          errors: result.errors,
          failure: result.failure ?? {
            kind: 'invalid_response',
            code: 'missing_create_role_payload',
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

      clearDraft(DRAFT_KEY)
      toast.success(t('rolesCreateSuccessToast'), {
        description: t('rolesCreateCommitted'),
      })
      if (result.partial) toast.warning(t('rbacPartialMutationNote'))

      if (scope.rolesRead) {
        void navigate({
          to: '/roles/$roleId',
          params: { roleId: payload.roleId },
          replace: true,
        })
      } else {
        setCreated({ roleId: payload.roleId, version: payload.version })
      }
    } catch {
      setFeedback({
        errors: [],
        failure: { kind: 'network', code: 'role_create_request_failed' },
        forbidden: false,
      })
    } finally {
      submitting.current = false
      setPending(false)
    }
  }

  return (
    <>
      {header}
      <ConsoleWorkspaceGate>
        <RoleCreateForm
          draft={draft}
          setDraft={setDraft}
          localErrors={localErrors}
          setLocalErrors={setLocalErrors}
          fieldErrors={fieldErrors}
          setFieldErrors={setFieldErrors}
          feedback={feedback}
          setFeedback={setFeedback}
          pending={pending}
          disabled={!scope.rolesWrite}
          showWriteOnlyWarning={!scope.rolesRead}
          onCreate={() => void submit()}
        />
      </ConsoleWorkspaceGate>
    </>
  )
}

function RoleCreateForm({
  draft,
  setDraft,
  localErrors,
  setLocalErrors,
  fieldErrors,
  setFieldErrors,
  feedback,
  setFeedback,
  pending,
  disabled,
  showWriteOnlyWarning,
  onCreate,
}: {
  draft: LocalizedDraft
  setDraft: (next: LocalizedDraft) => void
  localErrors: Partial<Record<LocalField, MessageKey>>
  setLocalErrors: React.Dispatch<
    React.SetStateAction<Partial<Record<LocalField, MessageKey>>>
  >
  fieldErrors: Record<string, string>
  setFieldErrors: React.Dispatch<React.SetStateAction<Record<string, string>>>
  feedback: RbacFeedbackState | null
  setFeedback: (next: RbacFeedbackState | null) => void
  pending: boolean
  disabled: boolean
  showWriteOnlyWarning: boolean
  onCreate: () => void
}) {
  const t = useTranslator()
  const navigate = useNavigate()

  function change(field: 'names' | 'descriptions', value: LocalizedValues) {
    setDraft({ ...draft, [field]: value })
    setFeedback(null)
    setLocalErrors((current) => {
      if (!current.metadata) return current
      const next = { ...current }
      delete next.metadata
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

  return (
    <div className="space-y-4">
      {feedback ? <RbacMutationFeedback feedback={feedback} /> : null}
      <form
        noValidate
        aria-busy={pending}
        onSubmit={(event) => {
          event.preventDefault()
          onCreate()
        }}
      >
        <div className="space-y-4">
          <Card className="console-card border border-border">
            <Card.Header className="border-b border-separator px-5 py-4">
              <Card.Title className="text-base font-semibold">
                {t('rolesMetadataSectionTitle')}
              </Card.Title>
              <Card.Description className="mt-1 text-sm text-muted">
                {t('rolesMetadataSectionDescription')}
              </Card.Description>
            </Card.Header>
            <Card.Content className="p-5">
              <div className="space-y-4">
                <LocalizedTextField
                  name="names"
                  label={t('localizedName')}
                  defaultValue={draft.name}
                  onDefaultValueChange={(value) => {
                    setDraft({ ...draft, name: value })
                    setFeedback(null)
                    setLocalErrors({})
                    setFieldErrors({})
                  }}
                  value={draft.names}
                  onChange={(value) => change('names', value)}
                  isRequired
                  isDisabled={pending || disabled}
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
                  defaultValue={draft.description}
                  onDefaultValueChange={(value) => {
                    setDraft({ ...draft, description: value })
                    setFeedback(null)
                    setLocalErrors({})
                    setFieldErrors({})
                  }}
                  value={draft.descriptions}
                  onChange={(value) => change('descriptions', value)}
                  multiline
                  isDisabled={pending || disabled}
                  maxLength={1024}
                  error={fieldErrors.description ?? fieldErrors.descriptions}
                />
              </div>
            </Card.Content>
          </Card>

          <div className="flex flex-wrap gap-2">
            <Button type="submit" isDisabled={pending || disabled}>
              {pending ? (
                <Spinner size="sm" aria-label={t('rolesCreatePending')} />
              ) : (
                <Plus className="size-4" aria-hidden="true" />
              )}
              {t('rolesCreateAction')}
            </Button>
            <Button
              type="button"
              variant="secondary"
              isDisabled={pending}
              onPress={() => void navigate({ to: '/roles' })}
            >
              {t('cancel')}
            </Button>
          </div>
        </div>
      </form>
      {showWriteOnlyWarning && !disabled && !pending ? (
        <Alert status="warning">
          <Alert.Indicator />
          <Alert.Content>
            <Alert.Title>{t('rolesNoReadAfterCreateTitle')}</Alert.Title>
            <Alert.Description>
              {t('rolesNoReadAfterCreateDescription')}
            </Alert.Description>
          </Alert.Content>
        </Alert>
      ) : null}
    </div>
  )
}
