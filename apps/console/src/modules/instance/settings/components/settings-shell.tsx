import { Outlet, useRouterState } from '@tanstack/react-router'

import { PageHeader } from '#/components/page-header'
import { useTranslator } from '#/lib/i18n'
import { ConsoleWorkspaceGate } from '#/modules/user-management/components/workspace-gate'
import { SectionTabs, type SectionTab } from '../../components/section-tabs'
import { InstanceSettingsProvider, useInstanceSettings } from './instance-settings-context'

type SettingsPath =
  | '/settings'
  | '/settings/protocol'
  | '/settings/authentication'
  | '/settings/signing-keys'
  | '/settings/encryption-keys'

const tabs: ReadonlyArray<
  SectionTab<SettingsPath> & {
    /** Which read the tab's content needs. */
    read: 'settings' | 'keys'
  }
> = [
  { to: '/settings', label: 'settingsTabGeneral', read: 'settings' },
  { to: '/settings/protocol', label: 'settingsTabProtocol', read: 'settings' },
  { to: '/settings/authentication', label: 'settingsTabAuthentication', read: 'settings' },
  { to: '/settings/signing-keys', label: 'settingsTabSigningKeys', read: 'keys' },
  { to: '/settings/encryption-keys', label: 'settingsTabEncryptionKeys', read: 'keys' },
]

export function SettingsShell() {
  return (
    <InstanceSettingsProvider>
      <SettingsLayout />
    </InstanceSettingsProvider>
  )
}

function SettingsLayout() {
  const t = useTranslator()
  const { scope, keys, permissionsPending } = useInstanceSettings()
  const pathname = useRouterState({ select: (state) => state.location.pathname })
  return (
    <>
      <PageHeader title={t('settingsTitle')} description={t('settingsDescription')} />
      <SectionTabs
        label={t('settingsTabs')}
        tabs={tabs}
        pathname={pathname}
        // Every tab stays while permissions load, so the row does not jump.
        visible={(tab) =>
          permissionsPending || (tab.read === 'settings' ? scope.read : keys.read)
        }
      />
      {/* While permissions load, the routed page shows its own skeleton. */}
      <ConsoleWorkspaceGate loading={<Outlet />}>
        <Outlet />
      </ConsoleWorkspaceGate>
    </>
  )
}
