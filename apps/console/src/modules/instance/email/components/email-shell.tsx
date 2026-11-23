import { Outlet, useRouterState } from '@tanstack/react-router'

import { PageHeader } from '#/components/page-header'
import { useTranslator } from '#/lib/i18n'
import { ConsoleWorkspaceGate } from '#/modules/user-management/components/workspace-gate'
import { SectionTabs, type SectionTab } from '../../components/section-tabs'
import { InstanceSettingsProvider } from '../../settings/components/instance-settings-context'

const tabs: ReadonlyArray<SectionTab<'/email' | '/email/templates'>> = [
  { to: '/email', label: 'emailTabDelivery' },
  { to: '/email/templates', label: 'emailTabTemplates' },
]

/** How the instance sends email and what it sends, beside the other instance settings. */
export function EmailShell() {
  const t = useTranslator()
  const pathname = useRouterState({ select: (state) => state.location.pathname })
  return (
    <InstanceSettingsProvider>
      <PageHeader title={t('emailTitle')} description={t('emailDescription')} />
      <SectionTabs label={t('emailTabs')} tabs={tabs} pathname={pathname} />
      {/* While permissions load, the routed page shows its own skeleton. */}
      <ConsoleWorkspaceGate loading={<Outlet />}>
        <Outlet />
      </ConsoleWorkspaceGate>
    </InstanceSettingsProvider>
  )
}
