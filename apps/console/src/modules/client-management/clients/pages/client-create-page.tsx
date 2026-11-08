import { Button } from '@identity/ui/components/button'
import {
  Field,
  FieldDescription,
  FieldLabel,
} from '@identity/ui/components/field'
import {
  RadioGroup,
  RadioGroupItem,
} from '@identity/ui/components/radio-group'
import { Spinner } from '@identity/ui/components/spinner'
import { useNavigate } from '@tanstack/react-router'
import { ArrowLeft, Plus } from 'lucide-react'
import { useEffect, useMemo, useRef, useState } from 'react'

import { LocalizedTextField } from '#/components/localized-text-field'
import { SettingsGroup, SettingsRow } from '#/components/settings-section'
import { PageHeader } from '#/components/page-header'
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
import {
  PublicClientFlowRow,
  CorsRow,
  GrantTypeRows,
  ParRow,
  RedirectUriRows,
} from '../components/client-settings-fields'
import { useClientMutations } from '../hooks/client-mutations'
import {
  clientFieldErrors,
  settingsForKind,
  kindUsesSecret,
  settingsInput,
  validateSettings,
  type ClientFieldErrors,
  type ClientKind,
  type ClientSettingsDraft,
} from '../lib/client-form'
import { clientScope } from '../lib/client-scope'

const DRAFT_KEY = 'identity.console.client-create.draft'

interface CreateDraft {
  kind: ClientKind
  text: LocalizedDraft
  settings: ClientSettingsDraft
}

const KINDS: ReadonlyArray<{ id: ClientKind; label: MessageKey; hint: MessageKey }> = [
  { id: 'web', label: 'clientsKindWeb', hint: 'clientsKindWebHint' },
  { id: 'spa', label: 'clientsKindSpa', hint: 'clientsKindSpaHint' },
  { id: 'native', label: 'clientsKindNative', hint: 'clientsKindNativeHint' },
  { id: 'machine', label: 'clientsKindMachine', hint: 'clientsKindMachineHint' },
]

function restoreDraft(): CreateDraft {
  const stored = readDraft<Partial<CreateDraft>>(DRAFT_KEY)
  const kind = KINDS.some((entry) => entry.id === stored?.kind)
    ? (stored?.kind as ClientKind)
    : 'web'
  return {
    kind,
    text: restoreLocalizedDraft(stored?.text),
    settings: { ...settingsForKind(kind), ...(stored?.settings ?? {}) },
  }
}

const noErrors: ClientFieldErrors = { settings: {}, text: {} }

export function ClientCreatePage() {
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
  const [nameError, setNameError] = useState<MessageKey | null>(null)
  const [feedback, setFeedback] = useState<RbacFeedbackState | null>(null)
  const [pending, setPending] = useState(false)

  useEffect(() => {
    writeDraft(DRAFT_KEY, draft)
  }, [draft])

  const header = (
    <PageHeader
      title={t('clientsNewTitle')}
      description={t('clientsNewDescription')}
      actions={
        <Button
          variant="secondary"
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
    setNameError(null)
  }

  async function submit() {
    if (submitting.current) return
    const local = validateSettings(draft.settings)
    const missingName = draft.text.name.trim() === ''
    if (missingName || Object.keys(local).length > 0) {
      setNameError(missingName ? 'clientsNameRequired' : null)
      setErrors({
        settings: Object.fromEntries(
          Object.entries(local).map(([field, key]) => [field, t(key)]),
        ),
        text: {},
      })
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
        setErrors(clientFieldErrors(result.errors))
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
        return
      }
      clearDraft(DRAFT_KEY)
      const needsSecret = kindUsesSecret(draft.kind)
      toast.success(t('clientsCreatedToast'), {
        description: t(
          needsSecret ? 'clientsCreatedNeedsSecret' : 'clientsCreatedCommitted',
        ),
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

  const fieldProps = {
    draft: draft.settings,
    onChange: (settings: ClientSettingsDraft) => update({ settings }),
    errors: errors.settings,
    isDisabled: pending,
  }

  return (
    <div className="w-full">
      {header}
      <ConsoleWorkspaceGate>
        <div className="space-y-4">
          {feedback ? <RbacMutationFeedback feedback={feedback} /> : null}
          <form
            noValidate
            aria-busy={pending}
            onSubmit={(event) => {
              event.preventDefault()
              void submit()
            }}
            className="space-y-6"
          >
            <SettingsGroup title={t('clientsKind')}>
              <SettingsRow description={t('clientsKindHint')}>
                <RadioGroup
                  name="client-kind"
                  aria-label={t('clientsKind')}
                  value={draft.kind}
                  disabled={pending}
                  onValueChange={(value: string) => {
                    const kind = value as ClientKind
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
                  }}
                >
                  <div className="grid gap-3 sm:grid-cols-2">
                    {KINDS.map((kind) => (
                      <Field key={kind.id} orientation="horizontal">
                        <RadioGroupItem
                          value={kind.id}
                          id={`client-kind-${kind.id}`}
                        />
                        <div className="min-w-0">
                          <FieldLabel
                            htmlFor={`client-kind-${kind.id}`}
                            className="font-normal"
                          >
                            {t(kind.label)}
                          </FieldLabel>
                          <FieldDescription>{t(kind.hint)}</FieldDescription>
                        </div>
                      </Field>
                    ))}
                  </div>
                </RadioGroup>
              </SettingsRow>
            </SettingsGroup>
            <SettingsGroup title={t('clientsBasicSection')}>
              <SettingsRow>
                <LocalizedTextField
                  name="names"
                  label={t('localizedName')}
                  defaultValue={draft.text.name}
                  onDefaultValueChange={(name) =>
                    update({ text: { ...draft.text, name } })
                  }
                  value={draft.text.names}
                  onChange={(names) => update({ text: { ...draft.text, names } })}
                  isDisabled={pending}
                  isRequired
                  maxLength={256}
                  error={
                    nameError ? t(nameError) : (errors.text.name ?? errors.text.names)
                  }
                />
              </SettingsRow>
              <SettingsRow>
                <LocalizedTextField
                  name="descriptions"
                  label={t('localizedDescription')}
                  defaultValue={draft.text.description}
                  onDefaultValueChange={(description) =>
                    update({ text: { ...draft.text, description } })
                  }
                  value={draft.text.descriptions}
                  onChange={(descriptions) =>
                    update({ text: { ...draft.text, descriptions } })
                  }
                  isDisabled={pending}
                  multiline
                  maxLength={1024}
                  error={errors.text.description ?? errors.text.descriptions}
                />
              </SettingsRow>
            </SettingsGroup>
            <SettingsGroup title={t('clientsRedirectSection')}>
              <RedirectUriRows {...fieldProps} />
            </SettingsGroup>
            <SettingsGroup title={t('clientsCorsSection')}>
              <CorsRow {...fieldProps} />
            </SettingsGroup>
            <SettingsGroup title={t('clientsGrantTypes')}>
              <GrantTypeRows {...fieldProps} />
            </SettingsGroup>
            <SettingsGroup
              title={t('clientsPublicClientSection')}
              description={t('clientsPublicClientSectionHint')}
            >
              <PublicClientFlowRow {...fieldProps} />
            </SettingsGroup>
            <SettingsGroup title={t('clientsAuthorizationRequestsSection')}>
              <ParRow {...fieldProps} />
            </SettingsGroup>
            <div className="flex flex-wrap justify-end gap-2">
              <Button type="submit" disabled={pending}>
                {pending ? (
                  <Spinner aria-label={t('clientsCreatePending')} />
                ) : (
                  <Plus className="size-4" aria-hidden="true" />
                )}
                {t('clientsCreateAction')}
              </Button>
              <Button
                type="button"
                variant="secondary"
                disabled={pending}
                onClick={() => void navigate({ to: '/clients' })}
              >
                {t('cancel')}
              </Button>
            </div>
          </form>
        </div>
      </ConsoleWorkspaceGate>
    </div>
  )
}
