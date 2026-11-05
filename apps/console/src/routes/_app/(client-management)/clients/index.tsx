import { createFileRoute } from '@tanstack/react-router'
import { ClientsListPage } from '#/modules/client-management/clients/pages/clients-list-page'
import { normalizeClientsSearch } from '#/modules/client-management/clients/lib/clients-search'
export const Route = createFileRoute('/_app/(client-management)/clients/')({
  staticData: {
    breadcrumbs: [
      { label: 'navClientManagement', link: false },
      { label: 'clientsTitle', to: '/clients' },
    ],
  },
  validateSearch: normalizeClientsSearch,
  component: () => <ClientsListPage search={Route.useSearch()} />,
})
