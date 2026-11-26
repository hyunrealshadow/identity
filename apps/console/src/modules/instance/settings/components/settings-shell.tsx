import { Outlet, useRouterState } from '@tanstack/react-router'
import { Globe, KeyRound, LockKeyhole, ShieldCheck, SlidersHorizontal } from 'lucide-react'

import { PageHeader } from '#/components/page-header'
import { useTranslator } from '#/lib/i18n'
import { ConsoleWorkspaceGate } from '#/components/workspace-gate'
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
  { to: '/settings', label: 'settingsTabGeneral', icon: SlidersHorizontal, read: 'settings' },
  { to: '/settings/protocol', label: 'settingsTabProtocol', icon: Globe, read: 'settings' },
  {
    to: '/settings/authentication',
    label: 'settingsTabAuthentication',
    icon: ShieldCheck,
    read: 'settings',
  },
  { to: '/settings/signing-keys', label: 'settingsTabSigningKeys', icon: KeyRound, read: 'keys' },
  {
    to: '/settings/encryption-keys',
    label: 'settingsTabEncryptionKeys',
    icon: LockKeyhole,
    read: 'keys',
  },
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
