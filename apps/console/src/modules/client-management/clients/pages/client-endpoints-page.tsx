import { AsyncState } from '#/components/async-state'
import { CopyableValue } from '#/components/copy-button'
import { SettingsGroup, SettingsRow } from '#/components/settings-section'
import { useTranslator, type MessageKey } from '#/lib/i18n'
import { useClientEndpoints } from '../hooks/use-client-endpoints'
import { useClientDetail } from '../components/client-detail-shell'

interface EndpointEntry {
  label: MessageKey
  value: string | null | undefined
}

function EndpointRows({ entries }: { entries: readonly EndpointEntry[] }) {
  const t = useTranslator()
  return (
    <>
      {entries
        .filter((entry): entry is EndpointEntry & { value: string } => Boolean(entry.value))
        .map((entry) => (
          <SettingsRow key={entry.label} label={t(entry.label)}>
            <CopyableValue value={entry.value} label={t(entry.label)} layout="block" />
          </SettingsRow>
        ))}
    </>
  )
}

/**
 * Endpoint URLs this client integrates with. The values come from the provider's
 * discovery metadata, so they always match the published well-known documents.
 */
export function ClientEndpointsPage() {
  const t = useTranslator()
  const { client } = useClientDetail()
  const endpoints = useClientEndpoints()

  return (
    <div className="space-y-6">
      {endpoints.status === 'loading' ? (
        <AsyncState kind="loading" />
      ) : endpoints.status === 'error' || !endpoints.data ? (
        <AsyncState
          kind="error"
          issues={endpoints.errors}
          requestId={endpoints.requestId}
          traceId={endpoints.traceId}
          onRetry={() => void endpoints.refresh()}
        />
      ) : (
        <div className="space-y-8">
          <SettingsGroup title={t('clientsEndpointsSectionDiscovery')}>
            <EndpointRows
              entries={[
                { label: 'clientsClientId', value: client?.id },
                { label: 'clientsEndpointsIssuer', value: endpoints.data.issuer },
                {
                  label: 'clientsEndpointsOpenIdConfiguration',
                  value: endpoints.data.openidConfigurationUrl,
                },
                {
                  label: 'clientsEndpointsOAuthAuthorizationServer',
                  value: endpoints.data.oauthAuthorizationServerMetadataUrl,
                },
                { label: 'clientsEndpointsJwks', value: endpoints.data.jwksUri },
              ]}
            />
          </SettingsGroup>

          <SettingsGroup title={t('clientsEndpointsSectionOAuth')}>
            <EndpointRows
              entries={[
                {
                  label: 'clientsEndpointsAuthorizationEndpoint',
                  value: endpoints.data.authorizationEndpoint,
                },
                {
                  label: 'clientsEndpointsTokenEndpoint',
                  value: endpoints.data.tokenEndpoint,
                },
                {
                  label: 'clientsEndpointsParEndpoint',
                  value: endpoints.data.pushedAuthorizationRequestEndpoint,
                },
                {
                  label: 'clientsEndpointsRevocationEndpoint',
                  value: endpoints.data.revocationEndpoint,
                },
                {
                  label: 'clientsEndpointsIntrospectionEndpoint',
                  value: endpoints.data.introspectionEndpoint,
                },
                {
                  label: 'clientsEndpointsDeviceEndpoint',
                  value: endpoints.data.deviceAuthorizationEndpoint,
                },
                {
                  label: 'clientsEndpointsRegistrationEndpoint',
                  value: endpoints.data.registrationEndpoint,
                },
              ]}
            />
          </SettingsGroup>

          <SettingsGroup title={t('clientsEndpointsSectionOpenId')}>
            <EndpointRows
              entries={[
                {
                  label: 'clientsEndpointsUserinfoEndpoint',
                  value: endpoints.data.userinfoEndpoint,
                },
                {
                  label: 'clientsEndpointsEndSessionEndpoint',
                  value: endpoints.data.endSessionEndpoint,
                },
                {
                  label: 'clientsEndpointsCheckSessionIframe',
                  value: endpoints.data.checkSessionIframe,
                },
              ]}
            />
          </SettingsGroup>
        </div>
      )}
    </div>
  )
}
