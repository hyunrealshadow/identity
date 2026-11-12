import { createFileRoute } from '@tanstack/react-router'
import { ProtocolSettingsPage } from '#/modules/instance/settings/pages/protocol-settings-page'
export const Route = createFileRoute('/_app/(instance)/settings/protocol')({
  staticData: {
    // The settings route above contributes the leading crumbs.
    breadcrumbs: [{ label: 'settingsTabProtocol' }],
  },
  component: ProtocolSettingsPage,
})
