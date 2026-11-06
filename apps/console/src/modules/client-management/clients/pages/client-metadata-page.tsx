import { AsyncState } from '#/components/async-state'
import { CopyButton } from '#/components/copy-button'
import { SettingsGroup, SettingsRow } from '#/components/settings-section'
import { useTranslator, type MessageKey } from '#/lib/i18n'
import { useClientMetadata } from '../hooks/use-client-metadata'
import { useClientDetail } from '../components/client-detail-shell'

interface MetadataEntry {
  label: MessageKey
  value: string | null | undefined
}

function MetadataRows({ entries }: { entries: readonly MetadataEntry[] }) {
  const t = useTranslator()
  return (
    <>
      {entries
        .filter((entry): entry is MetadataEntry & { value: string } => Boolean(entry.value))
        .map((entry) => (
          <SettingsRow
            key={entry.label}
            label={t(entry.label)}
            action={<CopyButton value={entry.value} label={t(entry.label)} />}
          >
            <code className="block break-all rounded-field bg-surface-secondary px-3 py-2 text-xs text-foreground">
              {entry.value}
            </code>
          </SettingsRow>
        ))}
    </>
  )
}

/**
 * Endpoint URLs this client integrates with. The values come from the provider's
 * discovery metadata, so they always match the published well-known documents.
 */
export function ClientMetadataPage() {
  const t = useTranslator()
  const { client } = useClientDetail()
  const metadata = useClientMetadata()

  return (
    <div className="space-y-6">
      <p className="max-w-2xl text-sm leading-6 text-muted">
        {t('clientsMetadataDescription')}
      </p>

      {metadata.status === 'loading' ? (
        <AsyncState kind="loading" />
      ) : metadata.status === 'error' || !metadata.data ? (
        <AsyncState
          kind="error"
          issues={metadata.errors}
          requestId={metadata.requestId}
          traceId={metadata.traceId}
          onRetry={() => void metadata.refresh()}
        />
      ) : (
        <div className="space-y-8">
          <SettingsGroup title={t('clientsMetadataSectionDiscovery')}>
            <MetadataRows
              entries={[
                { label: 'clientsClientId', value: client?.clientId },
                { label: 'clientsMetadataIssuer', value: metadata.data.issuer },
                {
                  label: 'clientsMetadataOpenIdConfiguration',
                  value: metadata.data.openidConfigurationUrl,
                },
                {
                  label: 'clientsMetadataOAuthAuthorizationServer',
                  value: metadata.data.oauthAuthorizationServerMetadataUrl,
                },
                { label: 'clientsMetadataJwks', value: metadata.data.jwksUri },
              ]}
            />
          </SettingsGroup>

          <SettingsGroup title={t('clientsMetadataSectionOAuth')}>
            <MetadataRows
              entries={[
                {
                  label: 'clientsMetadataAuthorizationEndpoint',
                  value: metadata.data.authorizationEndpoint,
                },
                {
                  label: 'clientsMetadataTokenEndpoint',
                  value: metadata.data.tokenEndpoint,
                },
                {
                  label: 'clientsMetadataParEndpoint',
                  value: metadata.data.pushedAuthorizationRequestEndpoint,
                },
                {
                  label: 'clientsMetadataRevocationEndpoint',
                  value: metadata.data.revocationEndpoint,
                },
                {
                  label: 'clientsMetadataIntrospectionEndpoint',
                  value: metadata.data.introspectionEndpoint,
                },
                {
                  label: 'clientsMetadataDeviceEndpoint',
                  value: metadata.data.deviceAuthorizationEndpoint,
                },
                {
                  label: 'clientsMetadataRegistrationEndpoint',
                  value: metadata.data.registrationEndpoint,
                },
              ]}
            />
          </SettingsGroup>

          <SettingsGroup title={t('clientsMetadataSectionOpenId')}>
            <MetadataRows
              entries={[
                {
                  label: 'clientsMetadataUserinfoEndpoint',
                  value: metadata.data.userinfoEndpoint,
                },
                {
                  label: 'clientsMetadataEndSessionEndpoint',
                  value: metadata.data.endSessionEndpoint,
                },
                {
                  label: 'clientsMetadataCheckSessionIframe',
                  value: metadata.data.checkSessionIframe,
                },
              ]}
            />
          </SettingsGroup>
        </div>
      )}
    </div>
  )
}
