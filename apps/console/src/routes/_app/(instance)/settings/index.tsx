import { createFileRoute } from '@tanstack/react-router'
import { GeneralSettingsPage } from '#/modules/instance/settings/pages/general-settings-page'
export const Route = createFileRoute('/_app/(instance)/settings/')({
  component: GeneralSettingsPage,
})
