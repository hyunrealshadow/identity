import { Button, Spinner, toast } from '@heroui/react'
import { Save } from 'lucide-react'
import { useState } from 'react'

import { SettingsGroup } from '#/components/settings-section'
import { useTranslator } from '#/lib/i18n'
import { RbacMutationFeedback } from '#/modules/user-management/components/rbac-feedback'
import type { RbacFeedbackState } from '#/modules/user-management/lib/rbac-errors'
import { useClientMutations } from '../hooks/client-mutations'
import {
  clientFieldErrors,
  formSeed,
  settingsDraftFromClient,
  settingsInput,
  validateSettings,
  type ClientSettingsDraft,
} from '../lib/client-form'
import { useClientDetail, type ConsoleClient } from './client-detail-shell'
import { AuthMethodRows } from './client-settings-fields'

/**
 * How the client authenticates at the token endpoint, edited next to its
 * credentials. Settings are replaced as a whole, so the save sends the
 * client's current settings with only the method changed.
 */
export function ClientAuthMethodSection() {
  const { client } = useClientDetail()
  if (!client) return null
  return <AuthMethodForm key={formSeed(client)} client={client} />
}

function AuthMethodForm({ client }: { client: ConsoleClient }) {
  const t = useTranslator()
  const { query, scope } = useClientDetail()
  const mutations = useClientMutations()
  const [draft, setDraft] = useState<ClientSettingsDraft>(() =>
    settingsDraftFromClient(client),
  )
  const [error, setError] = useState<string | undefined>()
  const [feedback, setFeedback] = useState<RbacFeedbackState | null>(null)
  const [pending, setPending] = useState(false)

  const editable = scope.update && !client.builtIn
  const pick = (value: ClientSettingsDraft) => {
    const input = settingsInput(value)
    return JSON.stringify(input.tokenEndpointAuthMethods)
  }
  const dirty = pick(draft) !== pick(settingsDraftFromClient(client))

  async function save() {
    if (pending || !dirty) return
    // Any rule the new method breaks (for example a public client that still
    // uses client credentials) is reported here, where the change was made.
    const local = validateSettings(draft)
    const key = local.tokenEndpointAuthMethods ?? local.grantTypes
    if (key) {
      setError(t(key))
      return
    }
    setPending(true)
    setFeedback(null)
    try {
      const result = await mutations.update({
        id: client.id,
        expectedVersion: client.version,
        settings: settingsInput(draft),
      })
      if (!result.data?.updateClient) {
        const fields = clientFieldErrors(result.errors).settings
        setError(fields.tokenEndpointAuthMethods ?? fields.grantTypes)
        setFeedback({
          errors: result.errors,
          failure: result.failure ?? {
            kind: 'invalid_response',
            code: 'missing_update_client_payload',
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
      toast.success(t('clientsSavedToast'), {
        description: t('clientsSavedWithdrawn'),
      })
    } catch {
      setFeedback({
        errors: [],
        failure: { kind: 'network', code: 'client_update_request_failed' },
        forbidden: false,
      })
    } finally {
      setPending(false)
    }
  }

  return (
    <form
      noValidate
      aria-busy={pending}
      onSubmit={(event) => {
        event.preventDefault()
        void save()
      }}
    >
      <SettingsGroup
        title={t('clientsAuthMethodSection')}
        description={t('clientsAuthMethodsHint')}
        footer={
          editable && dirty ? (
            <>
              <span className="text-xs text-muted">{t('clientsSettingsWithdrawNote')}</span>
              <Button type="submit" isDisabled={pending}>
                {pending ? (
                  <Spinner size="sm" aria-label={t('clientsSavePending')} />
                ) : (
                  <Save className="size-4" aria-hidden="true" />
                )}
                {t('clientsAuthMethodSave')}
              </Button>
            </>
          ) : undefined
        }
      >
        {feedback ? (
          <div className="px-5 py-4 md:px-6">
            <RbacMutationFeedback
              feedback={feedback}
              onReload={() => void query.refresh()}
              reloadPending={query.refreshing}
            />
          </div>
        ) : null}
        <AuthMethodRows
          draft={draft}
          onChange={(next) => {
            setDraft(next)
            setError(undefined)
            setFeedback(null)
          }}
          errors={{ tokenEndpointAuthMethods: error }}
          isDisabled={pending || !editable}
        />
      </SettingsGroup>
    </form>
  )
}
