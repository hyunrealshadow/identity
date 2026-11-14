import {
  Alert,
  AlertDescription,
  AlertTitle,
} from '@identity/ui/components/alert'
import { Button } from '@identity/ui/components/button'
import {
  Card,
  CardContent,
} from '@identity/ui/components/card'
import { Spinner } from '@identity/ui/components/spinner'
import { useNavigate } from '@tanstack/react-router'
import { ArrowLeft, Plus, TriangleAlert } from 'lucide-react'
import { useEffect, useMemo, useRef, useState } from 'react'

import { toast } from '#/lib/toast'

import { LocalizedTextField } from '#/components/localized-text-field'
import { PageHeader } from '#/components/page-header'

import type { CreateGroupInput } from '#/generated/graphql'
import { useTranslator, type MessageKey } from '#/lib/i18n'
import { useWorkspace } from '#/lib/workspace'
import { RbacMutationFeedback } from '#/modules/user-management/components/rbac-feedback'
import { ConsoleWorkspaceGate } from '#/modules/user-management/components/workspace-gate'
import { useGroupMutations } from '#/modules/user-management/groups/hooks/group-mutations'
import {
  emptyGroupDraft,
  groupLocalizedMetadata,
  hasGroupName,
  restoreGroupTextDraft,
  type GroupTextDraft,
} from '#/modules/user-management/groups/lib/groups-draft'
import { clearDraft, readDraft, writeDraft } from '#/lib/draft-storage'
import {
  rbacFieldErrors,
  type RbacFeedbackState,
} from '#/modules/user-management/lib/rbac-errors'
import { rbacScope } from '#/modules/user-management/lib/rbac-scope'
import { RbacAccessRestricted } from '#/modules/user-management/roles/components/role-access'

const DRAFT_KEY = 'identity.console.group-create.draft'

type LocalField = 'name'

function restoreDraft(): GroupTextDraft {
  return restoreGroupTextDraft(readDraft<unknown>(DRAFT_KEY))
}

export function GroupCreatePage() {
  const t = useTranslator()
  const navigate = useNavigate()
  const workspace = useWorkspace()
  const scope = useMemo(
    () => rbacScope(workspace.data?.effectivePermissions),
    [workspace.data?.effectivePermissions],
  )
  const mutations = useGroupMutations()
  const submitting = useRef(false)
  const [draft, setDraft] = useState<GroupTextDraft>(restoreDraft)
  const [localErrors, setLocalErrors] = useState<
    Partial<Record<LocalField, MessageKey>>
  >({})
  const [fieldErrors, setFieldErrors] = useState<Record<string, string>>({})
  const [feedback, setFeedback] = useState<RbacFeedbackState | null>(null)
  const [pending, setPending] = useState(false)
  const [created, setCreated] = useState<{ groupId: string } | null>(null)

  useEffect(() => {
    writeDraft(DRAFT_KEY, draft)
  }, [draft])

  const header = (
    <PageHeader
      title={t('groupsNewTitle')}
      description={t('groupsNewDescription')}
      actions={
        <Button
          variant="outline"
          disabled={pending}
          onClick={() => void navigate({ to: '/groups' })}
        >
          <ArrowLeft className="size-4" aria-hidden="true" />
          {t('backToGroups')}
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
            <CardContent className="p-6 sm:p-8">
              <span className="flex size-10 items-center justify-center rounded-lg bg-muted text-muted-foreground">
                <Plus className="size-5" aria-hidden="true" />
              </span>
              <h2 className="mt-4 text-lg font-semibold tracking-tight">
                {t('groupsCreateWriteOnlyTitle')}
              </h2>
              <p className="mt-2 max-w-2xl text-sm leading-6 text-muted-foreground">
                {t('groupsCreateWriteOnlyDescription', {
                  groupId: created.groupId,
                })}
              </p>
              <dl className="mt-4 grid gap-3 text-sm sm:grid-cols-2">
                <div>
                  <dt className="text-xs font-medium text-muted-foreground">
                    {t('groupsIdLabel')}
                  </dt>
                  <dd className="mt-0.5 break-all font-mono text-xs">
                    {created.groupId}
                  </dd>
                </div>
              </dl>
              <div className="mt-5 flex flex-wrap gap-2">
                <Button
                  onClick={() => {
                    setCreated(null)
                    setDraft(emptyGroupDraft())
                    clearDraft(DRAFT_KEY)
                  }}
                >
                  <Plus className="size-4" aria-hidden="true" />
                  {t('groupsCreateAnother')}
                </Button>
                <Button
                  variant="outline"
                  onClick={() => void navigate({ to: '/groups' })}
                >
                  {t('backToGroups')}
                </Button>
              </div>
            </CardContent>
          </Card>
        </ConsoleWorkspaceGate>
      </>
    )
  }

  if (!scope.groupsWrite) {
    return (
      <>
        {header}
        <ConsoleWorkspaceGate>
          <RbacAccessRestricted
            title="groupsCreateNoPermissionTitle"
            description="groupsCreateNoPermissionDescription"

            onBack={() => void navigate({ to: '/groups' })}
            backLabel="backToGroups"
          />
        </ConsoleWorkspaceGate>
      </>
    )
  }

  function validate(current: GroupTextDraft): boolean {
    const next: Partial<Record<LocalField, MessageKey>> = {}
    if (!hasGroupName(current)) next.name = 'groupsNameRequired'
    setLocalErrors(next)
    return Object.keys(next).length === 0
  }

  async function submit() {
    if (submitting.current || !scope.groupsWrite) return
    if (!validate(draft)) return
    submitting.current = true
    setPending(true)
    setFeedback(null)
    setFieldErrors({})
    try {
      const metadata = groupLocalizedMetadata(draft)
      const input: CreateGroupInput = {
        name: metadata.name,
        description: metadata.description,
        names: metadata.names,
        descriptions: metadata.descriptions,
      }
      const result = await mutations.create(input)
      const payload = result.data?.createGroup ?? null
      if (!payload) {
        setFieldErrors(rbacFieldErrors(result.errors))
        setFeedback({
          errors: result.errors,
          failure: result.failure ?? {
            kind: 'invalid_response',
            code: 'missing_create_group_payload',
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
      toast.success(t('groupsCreateSuccessToast'), {
        description: t('groupsCreateCommitted'),
      })
      if (result.partial) toast.warning(t('rbacPartialMutationNote'))

      if (scope.groupsRead) {
        void navigate({
          to: '/groups/$groupId',
          params: { groupId: payload.groupId },
          replace: true,
        })
      } else {
        setCreated({ groupId: payload.groupId })
      }
    } catch {
      setFeedback({
        errors: [],
        failure: { kind: 'network', code: 'group_create_request_failed' },
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
        <GroupCreateForm
          draft={draft}
          setDraft={setDraft}
          localErrors={localErrors}
          setLocalErrors={setLocalErrors}
          fieldErrors={fieldErrors}
          setFieldErrors={setFieldErrors}
          feedback={feedback}
          setFeedback={setFeedback}
          pending={pending}
          disabled={!scope.groupsWrite}
          showWriteOnlyWarning={!scope.groupsRead}
          onCreate={() => void submit()}
        />
      </ConsoleWorkspaceGate>
    </>
  )
}

function GroupCreateForm({
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
  draft: GroupTextDraft
  setDraft: (next: GroupTextDraft) => void
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

  function changeNames(names: GroupTextDraft['names']) {
    setDraft({ ...draft, names })
    setFeedback(null)
    setLocalErrors((current) => {
      if (!current.name) return current
      const next = { ...current }
      delete next.name
      return next
    })
    setFieldErrors((current) => {
      if (!current.names) return current
      const next = { ...current }
      delete next.names
      return next
    })
  }

  function changeDescriptions(descriptions: GroupTextDraft['descriptions']) {
    setDraft({ ...draft, descriptions })
    setFeedback(null)
    setFieldErrors((current) => {
      if (!current.descriptions) return current
      const next = { ...current }
      delete next.descriptions
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
            <CardContent className="space-y-6 p-5">
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
                onChange={changeNames}
                isDisabled={pending || disabled}
                isRequired
                maxLength={256}
                error={
                  localErrors.name ? t(localErrors.name) : fieldErrors.names
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
                onChange={changeDescriptions}
                isDisabled={pending || disabled}
                multiline
                maxLength={1024}
                error={fieldErrors.description ?? fieldErrors.descriptions}
              />
            </CardContent>
          </Card>

          <div className="flex flex-wrap gap-2">
            <Button type="submit" disabled={pending || disabled}>
              {pending ? (
                <Spinner aria-label={t('groupsCreatePending')} />
              ) : (
                <Plus className="size-4" aria-hidden="true" />
              )}
              {t('groupsCreateAction')}
            </Button>
            <Button
              type="button"
              variant="outline"
              disabled={pending}
              onClick={() => void navigate({ to: '/groups' })}
            >
              {t('cancel')}
            </Button>
          </div>
        </div>
      </form>
      {showWriteOnlyWarning && !disabled && !pending ? (
        <Alert variant="default" className="text-warning">
          <TriangleAlert aria-hidden="true" />
          <AlertTitle>{t('groupsNoReadAfterCreateTitle')}</AlertTitle>
          <AlertDescription>
            {t('groupsNoReadAfterCreateDescription')}
          </AlertDescription>
        </Alert>
      ) : null}
    </div>
  )
}
