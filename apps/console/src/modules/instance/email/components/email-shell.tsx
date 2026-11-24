import { Outlet, useMatch, useRouterState } from '@tanstack/react-router'
import { FileText, Send } from 'lucide-react'

import { PageHeader } from '#/components/page-header'
import { useTranslator } from '#/lib/i18n'
import { ConsoleWorkspaceGate } from '#/modules/user-management/components/workspace-gate'
import { SectionTabs, type SectionTab } from '../../components/section-tabs'
import { InstanceSettingsProvider } from '../../settings/components/instance-settings-context'

const tabs: ReadonlyArray<SectionTab<'/email' | '/email/templates'>> = [
  { to: '/email', label: 'emailTabDelivery', icon: Send },
  { to: '/email/templates', label: 'emailTabTemplates', icon: FileText },
]

/** How the instance sends email and what it sends, beside the other instance settings. */
export function EmailShell() {
  const t = useTranslator()
  const pathname = useRouterState({ select: (state) => state.location.pathname })
  const isTemplateDetail = Boolean(
    useMatch({ from: '/_app/(instance)/email/templates/$kind', shouldThrow: false }),
  )
  return (
    <InstanceSettingsProvider>
      {isTemplateDetail ? null : (
        <>
          <PageHeader title={t('emailTitle')} description={t('emailDescription')} />
          <SectionTabs label={t('emailTabs')} tabs={tabs} pathname={pathname} />
        </>
      )}
      {/* While permissions load, the routed page shows its own skeleton. */}
      <ConsoleWorkspaceGate loading={<Outlet />}>
        <Outlet />
      </ConsoleWorkspaceGate>
    </InstanceSettingsProvider>
  )
}
