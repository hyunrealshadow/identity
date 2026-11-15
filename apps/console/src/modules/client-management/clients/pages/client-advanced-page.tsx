import { AsyncState } from '#/components/async-state'
import { SettingsGroup, SettingsGroupSkeleton } from '#/components/settings-section'
import { useTranslator } from '#/lib/i18n'
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
import { useClientMetadataOptions } from '../hooks/use-client-metadata-options'
import { useClientEditor } from '../hooks/use-client-editor'
import { formSeed } from '../lib/client-form'

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
      <SettingsGroupSkeleton rows={['control']} />
      <SettingsGroupSkeleton rows={['control', 'switch', 'textarea']} />
      <SettingsGroupSkeleton rows={['textarea', 'textarea', 'textarea', 'switch', 'switch']} />
      <SettingsGroupSkeleton rows={['textarea', 'textarea']} />
    </div>
  )
}

function ClientAdvanced({ client }: { client: ConsoleClient }) {
  const t = useTranslator()
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

      <SettingsGroup title={t('clientsSubjectSection')}>
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
