import { createFileRoute } from '@tanstack/react-router'
import { SessionSettingsPage } from '#/modules/instance/settings/pages/session-settings-page'

export const Route = createFileRoute('/_app/(instance)/settings/session')({
  component: SessionSettingsPage,
})
