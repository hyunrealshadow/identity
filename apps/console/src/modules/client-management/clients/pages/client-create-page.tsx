import { Button } from '@identity/ui/components/button'
import { useNavigate } from '@tanstack/react-router'
import { ArrowLeft, ArrowRight, Plus } from 'lucide-react'
import { useEffect, useMemo, useRef, useState } from 'react'

import { PageHeader } from '#/components/page-header'
import { Stepper } from '#/components/stepper'
import { clearDraft, readDraft, writeDraft } from '#/lib/draft-storage'
import { useTranslator, type MessageKey } from '#/lib/i18n'
import {
  localizedMetadata,
  restoreLocalizedDraft,
  type LocalizedDraft,
} from '#/lib/localized-values'
import { toast } from '#/lib/toast'
import { useWorkspace } from '#/lib/workspace'
import { RbacMutationFeedback } from '#/modules/user-management/components/rbac-feedback'
import { ConsoleWorkspaceGate } from '#/modules/user-management/components/workspace-gate'
import type { RbacFeedbackState } from '#/modules/user-management/lib/rbac-errors'
import { RbacAccessRestricted } from '#/modules/user-management/roles/components/role-access'
import { CreateAccessStep } from '../components/create/create-access-step'
import { CreateDetailsStep } from '../components/create/create-details-step'
import { CLIENT_KINDS, CreateKindStep } from '../components/create/create-kind-step'
import { CreateRedirectsStep } from '../components/create/create-redirects-step'
import { CREATE_STEP_LABELS, CreateReviewStep } from '../components/create/create-review-step'
import { useClientMutations } from '../hooks/client-mutations'
import {
  clientFieldErrors,
  kindUsesSecret,
  settingsForKind,
  settingsInput,
  type ClientFieldErrors,
  type ClientKind,
  type ClientSettingsDraft,
} from '../lib/client-form'
import { clientScope } from '../lib/client-scope'
import {
  reachableStep,
  stepForField,
  stepsFor,
  validateStep,
  type CreateDraftShape,
  type CreateSearch,
  type CreateStep,
} from '../lib/create-steps'

const DRAFT_KEY = 'identity.console.client-create.draft'

interface CreateDraft {
  kind: ClientKind
  text: LocalizedDraft
  settings: ClientSettingsDraft
}

const STEP_HINTS: Record<CreateStep, MessageKey> = {
  kind: 'clientsCreateStepKindHint',
  details: 'clientsCreateStepDetailsHint',
  redirects: 'clientsCreateStepRedirectsHint',
  access: 'clientsCreateStepAccessHint',
  review: 'clientsCreateStepReviewHint',
}

function restoreDraft(): CreateDraft {
  const stored = readDraft<Partial<CreateDraft>>(DRAFT_KEY)
  const kind = CLIENT_KINDS.some((entry) => entry.id === stored?.kind)
    ? (stored?.kind as ClientKind)
    : 'web'
  return {
    kind,
    text: restoreLocalizedDraft(stored?.text),
    settings: { ...settingsForKind(kind), ...(stored?.settings ?? {}) },
  }
}

function shapeOf(draft: CreateDraft): CreateDraftShape {
  return { kind: draft.kind, name: draft.text.name, settings: draft.settings }
}

const noErrors: ClientFieldErrors = { settings: {}, text: {} }

export function ClientCreatePage({ search }: { search: CreateSearch }) {
  const t = useTranslator()
  const navigate = useNavigate()
  const workspace = useWorkspace()
  const scope = useMemo(
    () => clientScope(workspace.data?.effectivePermissions),
    [workspace.data?.effectivePermissions],
  )
  const mutations = useClientMutations()
  const submitting = useRef(false)
  const [draft, setDraft] = useState<CreateDraft>(restoreDraft)
  const [errors, setErrors] = useState<ClientFieldErrors>(noErrors)
  const [feedback, setFeedback] = useState<RbacFeedbackState | null>(null)
  const [pending, setPending] = useState(false)
  const headingRef = useRef<HTMLHeadingElement>(null)
  const draftRef = useRef(draft)
  draftRef.current = draft

  useEffect(() => {
    writeDraft(DRAFT_KEY, draft)
  }, [draft])

  const requested = search.step ?? 'kind'
  // Opening a later step (a bookmark, a reload, a hand-edited address) stops
  // at the first earlier step that is not finished. It is checked when the
  // address changes, not on every edit, so changing a setting never moves
  // the person off the step they are on.
  const step = useMemo(
    () => reachableStep(requested, shapeOf(draftRef.current)),
    [requested],
  )
  useEffect(() => {
    if (search.step && step !== search.step) {
      void navigate({ to: '/clients/new', search: { step }, replace: true })
    }
  }, [navigate, search.step, step])

  const firstRender = useRef(true)
  useEffect(() => {
    if (firstRender.current) {
      firstRender.current = false
      return
    }
    headingRef.current?.focus()
  }, [step])

  const shape = shapeOf(draft)
  const steps = stepsFor(shape)
  const index = Math.max(0, steps.indexOf(step))

  const header = (
    <PageHeader
      title={t('clientsNewTitle')}
      description={t('clientsNewDescription')}
      actions={
        <Button
          variant="outline"
          disabled={pending}
          onClick={() => void navigate({ to: '/clients' })}
        >
          <ArrowLeft className="size-4" aria-hidden="true" />
          {t('clientsBack')}
        </Button>
      }
    />
  )

  if (!scope.create) {
    return (
      <>
        {header}
        <ConsoleWorkspaceGate>
          <RbacAccessRestricted
            title="clientsCreateNoPermissionTitle"
            description="clientsCreateNoPermissionDescription"
            onBack={() => void navigate({ to: '/clients' })}
            backLabel="clientsBack"
          />
        </ConsoleWorkspaceGate>
      </>
    )
  }

  function update(next: Partial<CreateDraft>) {
    setDraft((current) => ({ ...current, ...next }))
    setFeedback(null)
    setErrors(noErrors)
  }

  function changeKind(kind: ClientKind) {
    // Keep entered addresses; reset only the kind-specific defaults.
    const preset = settingsForKind(kind)
    update({
      kind,
      settings: {
        ...preset,
        webRedirectUris: draft.settings.webRedirectUris,
        nativeRedirectUris: draft.settings.nativeRedirectUris,
        postLogoutRedirectUris: draft.settings.postLogoutRedirectUris,
      },
    })
  }

  function goTo(target: CreateStep) {
    setFeedback(null)
    void navigate({ to: '/clients/new', search: { step: target } })
  }

  function showLocalErrors(local: ReturnType<typeof validateStep>) {
    const { name, ...settings } = local
    setErrors({
      settings: Object.fromEntries(
        Object.entries(settings).map(([field, key]) => [field, t(key)]),
      ),
      text: name ? { name: t(name) } : {},
    })
  }

  function next() {
    const local = validateStep(step, shape)
    if (Object.keys(local).length > 0) {
      showLocalErrors(local)
      return
    }
    const following = steps[index + 1]
    if (following) goTo(following)
  }

  async function submit() {
    if (submitting.current) return
    const local = validateStep('review', shape)
    if (Object.keys(local).length > 0) {
      showLocalErrors(local)
      const target = Object.keys(local).map(stepForField).find(Boolean)
      if (target) goTo(target)
      return
    }
    submitting.current = true
    setPending(true)
    setFeedback(null)
    try {
      const text = localizedMetadata(draft.text)
      const result = await mutations.create({
        name: text.name,
        description: text.description,
        names: text.names,
        descriptions: text.descriptions,
        settings: settingsInput(draft.settings),
      })
      const payload = result.data?.createClient ?? null
      if (!payload) {
        const fieldErrors = clientFieldErrors(result.errors)
        setErrors(fieldErrors)
        setFeedback({
          errors: result.errors,
          failure: result.failure ?? {
            kind: 'invalid_response',
            code: 'missing_create_client_payload',
            requestId: result.requestId,
            traceId: result.traceId,
          },
          stepUp: result.stepUp,
          requestId: result.requestId,
          traceId: result.traceId,
          forbidden: result.forbidden,
        })
        // Lead back to the step that shows the first rejected field.
        const target = [...Object.keys(fieldErrors.text), ...Object.keys(fieldErrors.settings)]
          .map(stepForField)
          .find(Boolean)
        if (target && target !== step) {
          void navigate({ to: '/clients/new', search: { step: target } })
        }
        return
      }
      clearDraft(DRAFT_KEY)
      const needsSecret = kindUsesSecret(draft.kind)
      toast.success(t('clientsCreatedToast'), {
        description: t(needsSecret ? 'clientsCreatedNeedsSecret' : 'clientsCreatedCommitted'),
      })
      void navigate({
        to:
          needsSecret && scope.secretCreate
            ? '/clients/$clientId/credentials'
            : '/clients/$clientId',
        params: { clientId: payload.clientId },
        replace: true,
      })
    } catch {
      setFeedback({
        errors: [],
        failure: { kind: 'network', code: 'client_create_request_failed' },
        forbidden: false,
      })
    } finally {
      submitting.current = false
      setPending(false)
    }
  }

  const last = step === 'review'
  const settingsProps = {
    settings: draft.settings,
    onChange: (settings: ClientSettingsDraft) => update({ settings }),
    errors: errors.settings,
    isDisabled: pending,
  }

  return (
    <div className="w-full">
      {header}
      <ConsoleWorkspaceGate>
        <div className="space-y-6">
          <Stepper
            label={t('clientsCreateStepsLabel')}
            steps={steps.map((id) => ({ id, label: t(CREATE_STEP_LABELS[id]) }))}
            current={step}
            progress={t('clientsCreateStepProgress', {
              current: index + 1,
              total: steps.length,
            })}
            canSelect={(id) =>
              !pending &&
              (steps.indexOf(id) < index || reachableStep(id, shape) === id)
            }
            onSelect={goTo}
          />
          <form
            noValidate
            aria-busy={pending}
            aria-labelledby="client-create-step-title"
            onSubmit={(event) => {
              event.preventDefault()
              if (last) void submit()
              else next()
            }}
            className="space-y-6"
          >
            <div>
              <h2
                id="client-create-step-title"
                ref={headingRef}
                tabIndex={-1}
                className="text-lg font-semibold tracking-tight outline-none"
              >
                {t(CREATE_STEP_LABELS[step])}
              </h2>
              <p className="mt-1 text-sm leading-6 text-muted-foreground">
                {t(STEP_HINTS[step])}
              </p>
            </div>
            {feedback ? <RbacMutationFeedback feedback={feedback} /> : null}

            {step === 'kind' ? (
              <CreateKindStep kind={draft.kind} onChange={changeKind} isDisabled={pending} />
            ) : step === 'details' ? (
              <CreateDetailsStep
                text={draft.text}
                onChange={(text) => update({ text })}
                nameError={errors.text.name ?? errors.text.names}
                descriptionError={errors.text.description ?? errors.text.descriptions}
                isDisabled={pending}
              />
            ) : step === 'redirects' ? (
              <CreateRedirectsStep kind={draft.kind} {...settingsProps} />
            ) : step === 'access' ? (
              <CreateAccessStep {...settingsProps} />
            ) : (
              <CreateReviewStep
                kind={draft.kind}
                text={draft.text}
                settings={draft.settings}
                steps={steps}
                onEdit={goTo}
                isDisabled={pending}
              />
            )}

            <div className="flex flex-wrap items-center justify-between gap-2 border-t border-border pt-6">
              {index === 0 ? (
                <Button
                  type="button"
                  variant="outline"
                  disabled={pending}
                  onClick={() => void navigate({ to: '/clients' })}
                >
                  {t('cancel')}
                </Button>
              ) : (
                <Button
                  type="button"
                  variant="outline"
                  disabled={pending}
                  onClick={() => goTo(steps[index - 1] ?? 'kind')}
                >
                  <ArrowLeft aria-hidden="true" />
                  {t('clientsCreatePrevious')}
                </Button>
              )}
              <Button type="submit" loading={last && pending} disabled={!last && pending}>
                {last ? (
                  <>
                    {pending ? null : <Plus aria-hidden="true" />}
                    {t('clientsCreateAction')}
                  </>
                ) : (
                  <>
                    {t('clientsCreateNext')}
                    <ArrowRight aria-hidden="true" />
                  </>
                )}
              </Button>
            </div>
          </form>
        </div>
      </ConsoleWorkspaceGate>
    </div>
  )
}
