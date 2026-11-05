import { Button, Card, Spinner, toast } from '@heroui/react'
import { useNavigate } from '@tanstack/react-router'
import { ArrowLeft, Plus } from 'lucide-react'
import { useEffect, useMemo, useRef, useState } from 'react'

import { LocalizedTextField } from '#/components/localized-text-field'
import { PageHeader } from '#/components/page-header'

import { type CreateScopeInput } from '#/generated/graphql'
import { useTranslator, type MessageKey } from '#/lib/i18n'
import { localizedMetadata, type LocalizedValues } from '#/lib/localized-values'
import { useWorkspace } from '#/lib/workspace'
import { RbacMutationFeedback } from '#/modules/user-management/components/rbac-feedback'
import { ConsoleWorkspaceGate } from '#/modules/user-management/components/workspace-gate'
import { clearDraft, readDraft, writeDraft } from '#/lib/draft-storage'
import { rbacScope } from '#/modules/user-management/lib/rbac-scope'
import {
  permissionFieldErrors,
  type RbacFeedbackState,
} from '#/modules/client-management/resources/permissions/lib/permissions-errors'
import { usePermissionMutations } from '#/modules/client-management/resources/permissions/hooks/permission-mutations'
import {
  emptyPermissionCreateDraft,
  restorePermissionCreateDraft,
  type PermissionCreateDraft,
} from '#/modules/client-management/resources/permissions/lib/permissions-draft'
import { RbacAccessRestricted } from '#/modules/user-management/roles/components/role-access'
import { UserTextField } from '#/modules/user-management/users/components/user-form-fields'

const createDraftKey = (resourceId: string) =>
  `identity.console.resource.${resourceId}.permission-create.draft`

type LocalField = 'resourceId' | 'code' | 'metadata'

function readCreateDraft(resourceId: string): PermissionCreateDraft {
  return {
    ...restorePermissionCreateDraft(
      readDraft<Partial<PermissionCreateDraft>>(createDraftKey(resourceId)),
      emptyPermissionCreateDraft(),
    ),
    resourceId,
  }
}

export function PermissionCreatePage({ resourceId }: { resourceId: string }) {
  const DRAFT_KEY = createDraftKey(resourceId)
  const t = useTranslator()
  const navigate = useNavigate()
  const workspace = useWorkspace()
  const scope = useMemo(
    () => rbacScope(workspace.data?.effectivePermissions),
    [workspace.data?.effectivePermissions],
  )
  const mutations = usePermissionMutations()
  const submitting = useRef(false)
  const [draft, setDraft] = useState<PermissionCreateDraft>(() =>
    readCreateDraft(resourceId),
  )
  const [localErrors, setLocalErrors] = useState<
    Partial<Record<LocalField, MessageKey>>
  >({})
  const [fieldErrors, setFieldErrors] = useState<Record<string, string>>({})
  const [feedback, setFeedback] = useState<RbacFeedbackState | null>(null)
  const [pending, setPending] = useState(false)
  const [created, setCreated] = useState<{
    permissionId: string
  } | null>(null)

  useEffect(() => {
    writeDraft(DRAFT_KEY, draft)
  }, [draft])

  const header = (
    <PageHeader
      title={t('permissionsNewTitle')}
      description={t('permissionsNewDescription')}
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
                {t('permissionsCreateWriteOnlyTitle')}
              </h2>
              <p className="mt-2 max-w-2xl text-sm leading-6 text-muted">
                {t('permissionsCreateWriteOnlyDescription', {
                  permissionId: created.permissionId,
                })}
              </p>
              <dl className="mt-4 grid gap-3 text-sm sm:grid-cols-2">
                <div>
                  <dt className="text-xs font-medium text-muted">
                    {t('permissionsIdLabel')}
                  </dt>
                  <dd className="mt-0.5 break-all font-mono text-xs">
                    {created.permissionId}
                  </dd>
                </div>
              </dl>
              <div className="mt-5 flex flex-wrap gap-2">
                <Button
                  onPress={() => {
                    setCreated(null)
                    setDraft({ ...emptyPermissionCreateDraft(), resourceId })
                    clearDraft(DRAFT_KEY)
                  }}
                >
                  <Plus className="size-4" aria-hidden="true" />
                  {t('permissionsCreateAnother')}
                </Button>
                <Button
                  variant="secondary"
                  onPress={() =>
                    void navigate({
                      to: '/resources/$resourceId/permissions',
                      params: { resourceId },
                    })
                  }
                >
                  {t('backToPermissions')}
                </Button>
              </div>
            </Card.Content>
          </Card>
        </ConsoleWorkspaceGate>
      </>
    )
  }

  if (!scope.permissionWrite) {
    return (
      <>
        {header}
        <ConsoleWorkspaceGate>
          <RbacAccessRestricted
            title="permissionsCreateNoPermissionTitle"
            description="permissionsCreateNoPermissionDescription"

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

  function validate(current: PermissionCreateDraft): boolean {
    const next: Partial<Record<LocalField, MessageKey>> = {}
    if (!current.code.trim()) next.code = 'permissionsCodeRequired'
    if (!current.resourceId) next.resourceId = 'permissionsResourceRequired'
    if (!current.name.trim()) {
      next.metadata = 'permissionsMetadataNameRequired'
    }
    setLocalErrors(next)
    return Object.keys(next).length === 0
  }

  async function submit() {
    if (submitting.current || !scope.permissionWrite) return
    if (!validate(draft)) return
    submitting.current = true
    setPending(true)
    setFeedback(null)
    setFieldErrors({})
    try {
      const input: CreateScopeInput = {
        resourceId,
        code: draft.code.trim(),
        ...localizedMetadata(draft),
      }
      const result = await mutations.create(input)
      const payload = result.data?.createPermission ?? null
      if (!payload) {
        setFieldErrors(permissionFieldErrors(result.errors))
        setFeedback({
          errors: result.errors,
          failure: result.failure ?? {
            kind: 'invalid_response',
            code: 'missing_create_permission_payload',
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
      toast.success(t('permissionsCreateSuccessToast'))
      if (result.partial) toast.warning(t('rbacPartialMutationNote'))

      if (scope.permissionRead) {
        void navigate({
          to: '/resources/$resourceId/permissions/$permissionId',
          params: { resourceId, permissionId: payload.permissionId },
          replace: true,
        })
      } else {
        setCreated({ permissionId: payload.permissionId })
      }
    } catch {
      setFeedback({
        errors: [],
        failure: { kind: 'network', code: 'permission_create_request_failed' },
        forbidden: false,
      })
    } finally {
      submitting.current = false
      setPending(false)
    }
  }

  function renderForm(disabled: boolean) {
    return (
      <PermissionCreateForm
        draft={draft}
        setDraft={setDraft}
        localErrors={localErrors}
        setLocalErrors={setLocalErrors}
        fieldErrors={fieldErrors}
        setFieldErrors={setFieldErrors}
        feedback={feedback}
        setFeedback={setFeedback}
        pending={pending}
        disabled={disabled}
        resourceId={resourceId}
        onCreate={() => void submit()}
      />
    )
  }

  return (
    <>
      {header}
      <ConsoleWorkspaceGate>{renderForm(false)}</ConsoleWorkspaceGate>
    </>
  )
}

function PermissionCreateForm({
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
  resourceId,
  onCreate,
}: {
  draft: PermissionCreateDraft
  setDraft: (next: PermissionCreateDraft) => void
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
  resourceId: string
  onCreate: () => void
}) {
  const t = useTranslator()
  const navigate = useNavigate()

  function clearErrors(fields: LocalField[]) {
    setLocalErrors((current) => {
      if (!fields.some((field) => current[field])) return current
      const next = { ...current }
      for (const field of fields) delete next[field]
      return next
    })
    setFieldErrors((current) => {
      const targets = [
        ...fields,
        'metadata',
        'names',
        'descriptions',
        'resourceId',
      ]
      if (!targets.some((target) => current[target])) return current
      const next = { ...current }
      for (const target of targets) delete next[target]
      return next
    })
  }

  function change(field: 'code', value: string) {
    setDraft({ ...draft, [field]: value })
    setFeedback(null)
    clearErrors([field])
  }

  function changeMetadata(
    field: 'names' | 'descriptions',
    value: LocalizedValues,
  ) {
    setDraft({ ...draft, [field]: value })
    setFeedback(null)
    clearErrors(['metadata'])
  }

  const canSubmit = !pending && !disabled

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
                {t('permissionsSectionIdentity')}
              </Card.Title>
              <Card.Description className="mt-1 text-sm text-muted">
                {t('permissionsSectionIdentityDescription')}
              </Card.Description>
            </Card.Header>
            <Card.Content className="p-5">
              <div className="grid gap-4 sm:grid-cols-2">
                <UserTextField
                  name="code"
                  label={t('permissionsFieldCode')}
                  value={draft.code}
                  onChange={(value) => change('code', value)}
                  description={t('permissionsFieldCodeDescription')}
                  error={
                    fieldErrors.code ??
                    (localErrors.code ? t(localErrors.code) : undefined)
                  }
                  isRequired
                  isDisabled={pending || disabled}
                  maxLength={128}
                  autoComplete="off"
                />
              </div>
            </Card.Content>
          </Card>

          <Card className="console-card border border-border">
            <Card.Header className="border-b border-separator px-5 py-4">
              <Card.Title className="text-base font-semibold">
                {t('permissionsMetadataSectionTitle')}
              </Card.Title>
              <Card.Description className="mt-1 text-sm text-muted">
                {t('permissionsMetadataSectionDescription')}
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
                  onChange={(value) => changeMetadata('names', value)}
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
                  onChange={(value) => changeMetadata('descriptions', value)}
                  multiline
                  isDisabled={pending || disabled}
                  maxLength={1024}
                  error={fieldErrors.description ?? fieldErrors.descriptions}
                />
              </div>
            </Card.Content>
          </Card>

          <div className="flex flex-wrap gap-2">
            <Button type="submit" isDisabled={pending || !canSubmit}>
              {pending ? (
                <Spinner size="sm" aria-label={t('permissionsCreatePending')} />
              ) : (
                <Plus className="size-4" aria-hidden="true" />
              )}
              {t('permissionsCreateAction')}
            </Button>
            <Button
              type="button"
              variant="secondary"
              isDisabled={pending}
              onPress={() =>
                void navigate({
                  to: '/resources/$resourceId/permissions',
                  params: { resourceId },
                })
              }
            >
              {t('cancel')}
            </Button>
          </div>
        </div>
      </form>
    </div>
  )
}
