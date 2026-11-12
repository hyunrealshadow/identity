import { createFileRoute } from '@tanstack/react-router'
import { SettingsShell } from '#/modules/instance/settings/components/settings-shell'
export const Route = createFileRoute('/_app/(instance)/settings')({
  staticData: {
    breadcrumbs: [
      { label: 'navInstance', link: false },
      { label: 'settingsTitle', to: '/settings' },
    ],
  },
  component: SettingsShell,
})
