import { createFileRoute } from '@tanstack/react-router'
import { ClientCreatePage } from '#/modules/client-management/clients/pages/client-create-page'
import { normalizeCreateSearch } from '#/modules/client-management/clients/lib/create-steps'
export const Route = createFileRoute('/_app/(client-management)/clients/new')({
  staticData: {
    breadcrumbs: [
      { label: 'navClientManagement', link: false },
      { label: 'clientsTitle', to: '/clients' },
      { label: 'clientsNewTitle' },
    ],
  },
  validateSearch: normalizeCreateSearch,
  component: () => <ClientCreatePage search={Route.useSearch()} />,
})
