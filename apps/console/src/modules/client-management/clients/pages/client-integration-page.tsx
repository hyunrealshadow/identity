import {
  SettingsGroup,
  SettingsGroupSkeleton,
  SettingsRow,
} from '#/components/settings-section'
import { useTranslator } from '#/lib/i18n'
import { LogoutChannelRows } from '../components/advanced-fields'
import { useClientDetail, type ConsoleClient } from '../components/client-detail-shell'
import { ClientEditForm, useClientEditable } from '../components/client-edit-form'
import {
  CorsRow,
  GrantTypeRows,
  PublicClientFlowRow,
  RedirectUriRows,
} from '../components/client-settings-fields'
import { useClientEditor } from '../hooks/use-client-editor'
import { formSeed } from '../lib/client-form'

/** How an application signs users in and out: grants, redirects, logout, CORS. */
export function ClientIntegrationPage() {
  const { client } = useClientDetail()
  if (!client) return <ClientIntegrationSkeleton />
  return <ClientIntegration key={formSeed(client)} client={client} />
}

function ClientIntegrationSkeleton() {
  return (
    <div className="space-y-6" aria-busy="true">
      <SettingsGroupSkeleton rows={['switch', 'switch', 'switch', 'switch']} />
      <SettingsGroupSkeleton rows={['switch']} description />
      <SettingsGroupSkeleton rows={['textarea', 'textarea']} />
      <SettingsGroupSkeleton rows={['textarea', 'textarea', 'switch', 'textarea', 'switch']} />
      <SettingsGroupSkeleton rows={['switch']} />
    </div>
  )
}

function ClientIntegration({ client }: { client: ConsoleClient }) {
  const t = useTranslator()
  const editor = useClientEditor(client)
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
  }

  return (
    <ClientEditForm client={client} editor={editor}>
      <SettingsGroup title={t('clientsGrantTypes')}>
        <GrantTypeRows {...settings} />
      </SettingsGroup>

      <SettingsGroup
        title={t('clientsPublicClientSection')}
        description={t('clientsPublicClientSectionHint')}
      >
        <PublicClientFlowRow {...settings} />
      </SettingsGroup>

      <SettingsGroup title={t('clientsRedirectSection')}>
        <RedirectUriRows {...settings} include={['webRedirectUris', 'nativeRedirectUris']} />
      </SettingsGroup>

      <SettingsGroup title={t('clientsLogoutSection')} description={t('clientsLogoutSectionHint')}>
        <RedirectUriRows {...settings} include={['postLogoutRedirectUris']} />
        <LogoutChannelRows {...advanced} />
      </SettingsGroup>

      <SettingsGroup title={t('clientsCorsSection')}>
        <CorsRow {...settings} />
        {client.corsEnabled ? (
          <SettingsRow label={t('clientsCorsOrigins')} description={t('clientsCorsOriginsHint')}>
            {client.corsOrigins.length ? (
              <ul className="flex flex-wrap gap-2">
                {client.corsOrigins.map((origin) => (
                  <li key={origin}>
                    <code className="rounded-lg bg-muted px-2 py-1 text-xs">{origin}</code>
                  </li>
                ))}
              </ul>
            ) : (
              <p className="text-sm text-muted-foreground">{t('clientsCorsOriginsEmpty')}</p>
            )}
          </SettingsRow>
        ) : null}
      </SettingsGroup>
    </ClientEditForm>
  )
}
