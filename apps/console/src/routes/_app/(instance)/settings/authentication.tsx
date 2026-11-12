import { createFileRoute } from '@tanstack/react-router'
import { AuthenticationSettingsPage } from '#/modules/instance/settings/pages/authentication-settings-page'
export const Route = createFileRoute('/_app/(instance)/settings/authentication')({
  staticData: {
    // The settings route above contributes the leading crumbs.
    breadcrumbs: [{ label: 'settingsTabAuthentication' }],
  },
  component: AuthenticationSettingsPage,
})
