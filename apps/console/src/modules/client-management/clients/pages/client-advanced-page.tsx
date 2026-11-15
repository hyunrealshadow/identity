import { Button } from '@identity/ui/components/button'
import { useOverlayState } from '@identity/ui/hooks/use-overlay-state'
import { ShieldCheck, ShieldOff } from 'lucide-react'
import { useEffect, useState } from 'react'

import { AsyncState } from '#/components/async-state'
import { ConfirmationDialog } from '#/components/confirmation-dialog'
import {
  SettingsGroup,
  SettingsGroupSkeleton,
  SettingsRow,
} from '#/components/settings-section'
import { useTranslator } from '#/lib/i18n'
import { toast } from '#/lib/toast'
import { RbacMutationFeedback } from '#/modules/user-management/components/rbac-feedback'
import type { RbacFeedbackState } from '#/modules/user-management/lib/rbac-errors'
import {
  AuthenticationRequirementRows,
  ClientAssertionRow,
  InitiateLoginRow,
  RequestObjectRows,
  SubjectRows,
  TokenProtectionRows,
} from '../components/advanced-fields'
import { useClientDetail, type ConsoleClient } from '../components/client-detail-shell'
import { ClientEditForm, useClientEditable } from '../components/client-edit-form'
import {
  OAuthVersionRow,
  ParRow,
  ScopedClaimRows,
} from '../components/client-settings-fields'
import { useClientMutations } from '../hooks/client-mutations'
import { useClientMetadataOptions } from '../hooks/use-client-metadata-options'
import { mutationFeedback, useClientEditor } from '../hooks/use-client-editor'
import { formSeed, settingsDraftFromClient, settingsInput } from '../lib/client-form'

/**
 * Low-level protocol metadata. Choices come from what this instance supports
 * now; provider signing follows its active keys.
 */
export function ClientAdvancedPage() {
  const { client } = useClientDetail()
  if (!client) return <ClientAdvancedSkeleton />
  return <ClientAdvanced key={formSeed(client)} client={client} />
}

function ClientAdvancedSkeleton() {
  return (
    <div className="space-y-6" aria-busy="true">
      <SettingsGroupSkeleton rows={['control']} description />
      <SettingsGroupSkeleton rows={['switch', 'textarea', 'textarea', 'textarea', 'textarea']} />
      <SettingsGroupSkeleton rows={['control']} description />
      <SettingsGroupSkeleton rows={['control', 'switch', 'textarea']} />
      <SettingsGroupSkeleton rows={['textarea', 'textarea', 'textarea', 'switch', 'switch']} />
      <SettingsGroupSkeleton rows={['textarea', 'textarea']} />
    </div>
  )
}

function ClientAdvanced({ client }: { client: ConsoleClient }) {
  const t = useTranslator()
  const { scope } = useClientDetail()
  const editor = useClientEditor(client)
  const metadata = useClientMetadataOptions()
  const isDisabled = editor.pending || !useClientEditable(client)
  const settings = {
    draft: editor.settings,
    onChange: editor.setSettings,
    errors: editor.errors.settings,
    isDisabled,
  }
  const advanced = {
    draft: editor.advanced,
    onChange: editor.setAdvanced,
    errors: editor.errors.advanced,
    isDisabled,
    options: metadata.options,
  }

  return (
    <ClientEditForm
      client={client}
      editor={editor}
      after={!client.builtIn && scope.update ? <ClientConsent client={client} /> : null}
    >
      {metadata.status === 'error' ? (
        <AsyncState
          kind="error"
          title={t('clientsAlgorithmOptionsUnavailable')}
          issues={metadata.errors}
          requestId={metadata.requestId}
          traceId={metadata.traceId}
          onRetry={() => void metadata.refresh()}
        />
      ) : null}

      <SettingsGroup title={t('clientsOAuthSection')} description={t('clientsOAuthSectionHint')}>
        <OAuthVersionRow {...settings} />
      </SettingsGroup>

      <SettingsGroup title={t('clientsAuthorizationRequestsSection')}>
        <ParRow {...settings} />
        <RequestObjectRows {...advanced} />
      </SettingsGroup>

      <SettingsGroup title={t('clientsSubjectSection')} description={t('clientsSubjectSectionHint')}>
        <SubjectRows {...advanced} />
      </SettingsGroup>

      <SettingsGroup title={t('clientsAuthenticationRequirementsSection')}>
        <AuthenticationRequirementRows {...advanced} />
      </SettingsGroup>

      <SettingsGroup title={t('clientsTokenClaimsSection')}>
        <TokenProtectionRows {...advanced} />
        <ScopedClaimRows {...settings} />
      </SettingsGroup>

      <SettingsGroup title={t('clientsClientAuthenticationSection')}>
        <ClientAssertionRow {...advanced} />
        <InitiateLoginRow {...advanced} />
      </SettingsGroup>
    </ClientEditForm>
  )
}

/** Skipping consent takes effect immediately, after its own confirmation. */
function ClientConsent({ client }: { client: ConsoleClient }) {
  const t = useTranslator()
  const { query } = useClientDetail()
  const mutations = useClientMutations()
  const dialog = useOverlayState()
  const [pending, setPending] = useState(false)
  const [feedback, setFeedback] = useState<RbacFeedbackState | null>(null)

  useEffect(() => setFeedback(null), [client.version])

  async function setSkipConsent(skipConsent: boolean) {
    setPending(true)
    try {
      const result = await mutations.update({
        id: client.id,
        expectedVersion: client.version,
        settings: settingsInput({ ...settingsDraftFromClient(client), skipConsent }),
      })
      dialog.close()
      if (!result.data?.updateClient) {
        setFeedback(mutationFeedback(result, 'missing_update_client_payload'))
        return
      }
      toast.success(t('clientsSavedToast'), { description: t('clientsSavedWithdrawn') })
    } catch {
      dialog.close()
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
    <SettingsGroup title={t('clientsConsentSection')} tone="danger">
      {feedback ? (
        <div className="px-5 py-4">
          <RbacMutationFeedback
            feedback={feedback}
            onReload={() => void query.refresh()}
            reloadPending={query.refreshing}
          />
        </div>
      ) : null}
      <SettingsRow
        label={t('clientsSkipConsent')}
        description={t(client.skipConsent ? 'clientsSkipConsentOnHint' : 'clientsSkipConsentHint')}
        action={
          client.skipConsent ? (
            <Button
              variant="destructive"
              disabled={pending}
              onClick={() => void setSkipConsent(false)}
            >
              <ShieldCheck className="size-4" aria-hidden="true" />
              {t('clientsSkipConsentDisable')}
            </Button>
          ) : (
            <Button variant="destructive" onClick={dialog.open}>
              <ShieldOff className="size-4" aria-hidden="true" />
              {t('clientsSkipConsentEnable')}
            </Button>
          )
        }
      />
      <ConfirmationDialog
        state={dialog}
        title={t('clientsSkipConsentConfirmTitle')}
        description={t('clientsSkipConsentConfirmDescription')}
        confirmLabel={t('clientsSkipConsentEnable')}
        destructive
        pending={pending}
        onConfirm={() => void setSkipConsent(true)}
      />
    </SettingsGroup>
  )
}
