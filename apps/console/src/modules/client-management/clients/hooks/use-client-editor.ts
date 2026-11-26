import { useMemo, useState } from 'react'

import type { UpdateClientInput } from '#/generated/graphql'
import { useTranslator, type MessageKey } from '#/lib/i18n'
import {
  createLocalizedDraft,
  hasLocalizedDraftChanges,
  localizedMetadata,
  type LocalizedDraft,
} from '#/lib/localized-values'
import { toast } from '#/lib/toast'
import type { RbacFeedbackState } from '#/lib/rbac-errors'
import type { ConsoleClient } from '../components/client-detail-shell'
import {
  advancedDraftFromClient,
  advancedFieldFor,
  advancedInput,
  validateAdvanced,
  type ClientAdvancedDraft,
  type ClientAdvancedField,
} from '../lib/advanced-form'
import {
  clientFieldErrors,
  settingsDraftFromClient,
  settingsInput,
  validateSettings,
  type ClientSettingsDraft,
  type ClientSettingsField,
} from '../lib/client-form'
import { useClientMutations } from './client-mutations'

export interface ClientEditorErrors {
  settings: Partial<Record<ClientSettingsField, string>>
  advanced: Partial<Record<ClientAdvancedField, string>>
  /** Display text fields keyed by `name`, `names`, `description`, `descriptions`. */
  text: Record<string, string>
}

const noErrors: ClientEditorErrors = { settings: {}, advanced: {}, text: {} }

/**
 * Advanced fields that bound what the client may obtain. They mirror the
 * server's client boundary fingerprint, so a change withdraws issued tokens;
 * links, response signing and encryption preferences do not.
 */
const BOUNDARY_FIELDS: ReadonlySet<ClientAdvancedField> = new Set([
  'frontchannelLogoutUri',
  'frontchannelLogoutSessionRequired',
  'backchannelLogoutUri',
  'backchannelLogoutSessionRequired',
  'subjectType',
  'defaultMaxAge',
  'requireAuthTime',
  'defaultAcrValues',
  'requestObjectSigningAlgs',
  'requestObjectEncryptionAlgs',
  'requestObjectEncryptionEncs',
  'requestUris',
  'tokenEndpointAuthSigningAlgs',
])

interface MutationResultLike {
  errors: RbacFeedbackState['errors']
  failure?: RbacFeedbackState['failure']
  stepUp?: RbacFeedbackState['stepUp']
  requestId?: string
  traceId?: string
  forbidden: boolean
}

export function mutationFeedback(result: MutationResultLike, code: string): RbacFeedbackState {
  return {
    errors: result.errors,
    failure: result.failure ?? {
      kind: 'invalid_response',
      code,
      requestId: result.requestId,
      traceId: result.traceId,
    },
    stepUp: result.stepUp,
    requestId: result.requestId,
    traceId: result.traceId,
    forbidden: result.forbidden,
  }
}

function serverErrors(
  issues: Parameters<typeof clientFieldErrors>[0],
): ClientEditorErrors {
  const advanced: ClientEditorErrors['advanced'] = {}
  const rest = issues.map((issue) => ({
    ...issue,
    fields: issue.fields.filter((field) => {
      const key = advancedFieldFor(field.path)
      if (!key) return true
      advanced[key] ??=
        field.message ?? (field.code !== undefined ? String(field.code) : '')
      return false
    }),
  }))
  const { settings, text } = clientFieldErrors(rest)
  return { settings, advanced, text }
}

/**
 * One tab's edit of a client. Every tab starts from the full stored client and
 * sends only the units it changed, so fields another tab owns keep their
 * stored values. The optimistic version rejects a concurrent edit.
 */
export function useClientEditor(client: ConsoleClient) {
  const t = useTranslator()
  const mutations = useClientMutations()
  const [text, setTextState] = useState<LocalizedDraft>(() => createLocalizedDraft(client))
  const [settings, setSettingsState] = useState<ClientSettingsDraft>(() =>
    settingsDraftFromClient(client),
  )
  const [advanced, setAdvancedState] = useState<ClientAdvancedDraft>(() =>
    advancedDraftFromClient(client.advancedSettings),
  )
  const [errors, setErrors] = useState<ClientEditorErrors>(noErrors)
  const [nameError, setNameError] = useState<MessageKey | null>(null)
  const [feedback, setFeedback] = useState<RbacFeedbackState | null>(null)
  const [pending, setPending] = useState(false)

  const original = useMemo(
    () => ({
      settings: JSON.stringify(settingsInput(settingsDraftFromClient(client))),
      advanced: advancedInput(advancedDraftFromClient(client.advancedSettings)),
    }),
    [client],
  )
  const nextAdvanced = advancedInput(advanced)
  const settingsChanged = JSON.stringify(settingsInput(settings)) !== original.settings
  const changedAdvanced = (Object.keys(nextAdvanced) as Array<keyof typeof nextAdvanced>).filter(
    (key) => JSON.stringify(nextAdvanced[key]) !== JSON.stringify(original.advanced[key]),
  ) as ClientAdvancedField[]
  const advancedChanged = changedAdvanced.length > 0
  const textChanged = hasLocalizedDraftChanges(client, text)
  const dirty = settingsChanged || advancedChanged || textChanged
  /** Whether saving changes what the client may obtain, withdrawing its tokens. */
  const withdraws =
    settingsChanged ||
    changedAdvanced.some(
      (field) =>
        BOUNDARY_FIELDS.has(field) ||
        // Moving a pairwise sector moves every user's `sub`.
        (field === 'sectorIdentifierUri' && advanced.subjectType === 'PAIRWISE'),
    )

  function touched() {
    setFeedback(null)
    setErrors(noErrors)
    setNameError(null)
  }

  async function save(): Promise<boolean> {
    if (pending || !dirty) return false
    const localSettings = settingsChanged ? validateSettings(settings) : {}
    const localAdvanced = advancedChanged ? validateAdvanced(advanced) : {}
    const missingName = textChanged && text.name.trim() === ''
    const translate = <K extends string>(entries: Partial<Record<K, MessageKey>>) =>
      Object.fromEntries(
        Object.entries(entries).map(([field, key]) => [field, t(key as MessageKey)]),
      ) as Partial<Record<K, string>>
    if (
      missingName ||
      Object.keys(localSettings).length > 0 ||
      Object.keys(localAdvanced).length > 0
    ) {
      setNameError(missingName ? 'clientsNameRequired' : null)
      setErrors({
        settings: translate(localSettings),
        advanced: translate(localAdvanced),
        text: {},
      })
      return false
    }
    setPending(true)
    setFeedback(null)
    try {
      const input: UpdateClientInput = { id: client.id, expectedVersion: client.version }
      if (textChanged) Object.assign(input, localizedMetadata(text))
      if (settingsChanged) input.settings = settingsInput(settings)
      if (advancedChanged) input.advancedSettings = nextAdvanced
      const result = await mutations.update(input)
      if (!result.data?.updateClient) {
        setErrors(serverErrors(result.errors))
        setFeedback(mutationFeedback(result, 'missing_update_client_payload'))
        return false
      }
      toast.success(t('clientsSavedToast'), {
        description: t(withdraws ? 'clientsSavedWithdrawn' : 'clientsSavedCommitted'),
      })
      return true
    } catch {
      setFeedback({
        errors: [],
        failure: { kind: 'network', code: 'client_update_request_failed' },
        forbidden: false,
      })
      return false
    } finally {
      setPending(false)
    }
  }

  return {
    text,
    setText: (next: LocalizedDraft) => {
      setTextState(next)
      touched()
    },
    settings,
    setSettings: (next: ClientSettingsDraft) => {
      setSettingsState(next)
      touched()
    },
    advanced,
    setAdvanced: (next: ClientAdvancedDraft) => {
      setAdvancedState(next)
      touched()
    },
    errors,
    nameError,
    feedback,
    pending,
    dirty,
    withdraws,
    save,
  }
}

export type ClientEditor = ReturnType<typeof useClientEditor>
