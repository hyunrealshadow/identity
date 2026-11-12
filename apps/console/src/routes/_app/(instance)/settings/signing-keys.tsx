import { createFileRoute } from '@tanstack/react-router'
import { KeysSettingsPage } from '#/modules/instance/keys/pages/keys-settings-page'
import { normalizeKeysSearch } from '#/modules/instance/keys/lib/keys-search'
export const Route = createFileRoute('/_app/(instance)/settings/signing-keys')({
  staticData: {
    // The settings route above contributes the leading crumbs.
    breadcrumbs: [{ label: 'settingsTabSigningKeys' }],
  },
  validateSearch: normalizeKeysSearch,
  component: () => <KeysSettingsPage use="SIGNING" search={Route.useSearch()} />,
})
