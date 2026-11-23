import { createFileRoute } from '@tanstack/react-router'
import { EmailSettingsPage } from '#/modules/instance/settings/pages/email-settings-page'
export const Route = createFileRoute('/_app/(instance)/settings/email/')({
  staticData: {
    // The settings route above contributes the leading crumbs.
    breadcrumbs: [{ label: 'settingsTabEmail' }],
  },
  component: EmailSettingsPage,
})
